package Google::Cloud::Storage::Bucket;

use strict;
use warnings;

our $VERSION = '0.02';

use JSON qw(decode_json);

use JSON;
use Crypt::JWT qw(encode_jwt);
use Crypt::PK::RSA;

use LWP::UserAgent ();
use File::Basename qw(basename);

sub new {

    my ( $class, $self ) = @_;

    # Detect authentication method and validate required parameters
    my $has_service_account = (exists $self->{private_key_file} || exists $self->{private_key}) && exists $self->{client_email};
    my $has_oauth2 = exists $self->{client_id} && exists $self->{client_secret} && exists $self->{refresh_token};

    unless ( $has_service_account || $has_oauth2 ) {
        die "Must provide either Service Account credentials (private_key_file or private_key + client_email) or OAuth2 credentials (client_id + client_secret + refresh_token)";
    }

    unless ( exists $self->{bucket_name} ) {
        die "Required parameter bucket_name missing $!";
    }

    $self->{auth_method} = $has_service_account ? 'service_account' : 'oauth2';

    bless $self, $class;

    $self->_initialize();

    return $self;

}

sub _initialize {

    my $self = shift;

    # Only load private key for Service Account auth
    if ( $self->{auth_method} eq 'service_account' ) {
        # If private_key is not already set (as a string), load it from file
        if ( !exists $self->{'private_key'} && exists $self->{'private_key_file'} ) {
            $self->{'private_key'} = $self->_get_private_key();
        }
    }

    $self->{'access_token'} = $self->_authenticate();
}

sub _get_private_key {

    my $self = shift;

    open my $fh, '<', $self->{'private_key_file'} || die "Can't open google api private key file " . $self->{'private_key_file'} . " $!";
    binmode $fh;

    my $private_key = join( '', <$fh> );
    close $fh;

    return $private_key;

}

sub _authenticate {

    my $self = shift;

    if ( $self->{auth_method} eq 'service_account' ) {
        return $self->_authenticate_service_account();
    }
    else {
        return $self->_authenticate_oauth2();
    }

}

sub _authenticate_service_account {

    my $self = shift;

    my $url = 'https://oauth2.googleapis.com/token';
    my $exp = time() + 60 * 60;                        # Max ttl for token is 1 hour per Google

    # In _get_access_token method or in the constructor:
    my $exp = time() + 3600;

    # Check if private_key is JSON and parse it
    my $key;
    my $client_email = $self->{'client_email'};

    if ($self->{'private_key'} =~ /^\s*\{/) {
        # It's a JSON service account file
        my $json_data = decode_json($self->{'private_key'});
        $key = $json_data->{'private_key'};
        $client_email = $json_data->{'client_email'} unless $client_email;
    } else {
        # It's already just the key
        $key = $self->{'private_key'};
    }

    # Fix escaped newlines
    $key =~ s/\\n/\n/g;

    my $rsa_key = Crypt::PK::RSA->new(\$key);

    $self->{'jwt'} = encode_jwt(
        payload => {
            iss   => $client_email,
            exp   => $exp,
            aud   => 'https://oauth2.googleapis.com/token',
            scope => 'https://www.googleapis.com/auth/cloud-platform',
            iat   => time()
        },
        alg => 'RS256',
        key => $rsa_key
    );

    my $grant_string = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

    my $ua = LWP::UserAgent->new( timeout => 10 );

    my $response = $ua->post( $url, { grant_type => "$grant_string", assertion => $self->{'jwt'} } );

#    print STDERR "Token exchange status: " . $response->code . "\n";
#    print STDERR "Token exchange response: " . $response->content . "\n";

    my $access_token;
    if ( $response->is_success() ) {
        $access_token = decode_json( $response->decoded_content() );
    }
    else {
        die "Failed to authenticate to Google Cloud Storage (Service Account): " . $response->status_line();
    }
    $access_token->{expire_time} = $access_token->{expires_in} + time();

    return $access_token;

}

sub _authenticate_oauth2 {

    my $self = shift;

    my $url = 'https://oauth2.googleapis.com/token';

    my $ua = LWP::UserAgent->new( timeout => 10 );

    my $response = $ua->post(
        $url,
        {   grant_type    => 'refresh_token',
            client_id     => $self->{client_id},
            client_secret => $self->{client_secret},
            refresh_token => $self->{refresh_token}
        }
    );

    my $access_token;
    if ( $response->is_success() ) {
        $access_token = decode_json( $response->decoded_content() );
    }
    else {
        die "Failed to authenticate to Google Cloud Storage (OAuth2): " . $response->status_line();
    }
    $access_token->{expire_time} = $access_token->{expires_in} + time();

    return $access_token;

}

sub _refresh_access_token {

    my $self = shift;

    my $time_buffer = 60;

    if ( $self->{'access_token'}->{'expire_time'} - $time_buffer < time() ) {
        $self->{'access_token'} = $self->_authenticate();
    }

    return;

}

sub list_files {

    my $self      = shift;
    my $directory = shift;

    $self->_refresh_access_token();

    my $access_token = $self->{'access_token'}->{'access_token'};
    my $url          = 'https://storage.googleapis.com/storage/v1/b/' . $self->{'bucket_name'} . '/o';
    if ($directory) {
        $url .= "?prefix=$directory";
    }

    my $ua = LWP::UserAgent->new( timeout => 10 );

    $ua->default_header( 'Authorization' => 'Bearer ' . $access_token );

    my $response = $ua->get($url);

    if ( $response->is_success() ) {

        # response from GCS is not decoding the / character
        my $response_string = $response->decoded_content();
        $response_string =~ s/%2F/\//g;
        return decode_json($response_string);
    }
    else {
        die "Failed in call to list_files: " . $response->status_line();
    }
}

sub upload_file {

    my ( $self, $source, $content_type, $destination ) = @_;

    my $filename = basename($source);

    if ($destination) {
        $destination =~ s/\/$//;
        $destination .= '/';
    }
    else {
        $destination = "";
    }

    unless ( -e $source ) {
        die "Unable to locate file: $filename";
    }

    # Set default content-type to binary if it was not passed in by caller
    $content_type = 'application/octet-stream' unless ($content_type);

    my $access_token = $self->{'access_token'}->{'access_token'};

    my $url = 'https://storage.googleapis.com/upload/storage/v1/b/' . $self->{'bucket_name'} . '/o';
    $url .= '?name=' . $destination . $filename . '&uploadType=media';

    my @params;
    push @params, 'Authorization'   => 'Bearer ' . $access_token;
    push @params, 'Content-Type'    => $content_type if ($content_type);
    
    my $ua      = LWP::UserAgent->new();
    my $request = HTTP::Request->new(
        POST => $url,
        \@params
    );
    my $buffer;
    open my $fh, '<', $source || die "Can't open $source for reading. $!";
    $request->content(
        sub {

            if ( sysread( $fh, $buffer, 1048576 ) ) {
                return $buffer;
            }
            else {
                close $fh;
                return '';
            }
        }
    );
    my $response = $ua->request($request);

    if ( $response->is_success() ) {
        return decode_json( $response->decoded_content() );
    }
    else {
        die 'Upload Failed: ' . $response->status_line();
    }
}

sub upload_file_multipart {

    my ( $self, $bucket_name , $source, $content_type, $destination_key , $chunk_size_mb ) = @_;

    my $access_token = $self->{'access_token'}->{'access_token'};

    my $result = upload_file_resumable(
        $self->{'access_token'}->{'access_token'},
        $bucket_name,
        $destination_key,
        $source,
        $chunk_size_mb * 1024 * 1024
    );
    
    return $result;

}

sub upload_file_resumable {

    my ($access_token, $bucket, $object_name, $source_file, $chunk_size) = @_;
    
    $chunk_size ||= 5 * 1024 * 1024;  # Default 5MB chunks
    
    my $ua = LWP::UserAgent->new();
    
    # Debug: check what we're sending
#    print STDERR "Bucket: $bucket\n";
#    print STDERR "Object: $object_name\n";
#    print STDERR "Token (first 30): " . substr($access_token, 0, 30) . "...\n";

    # Step 1: Initiate resumable upload
    my $init_url = "https://storage.googleapis.com/upload/storage/v1/b/$bucket/o?uploadType=resumable";
#    print STDERR "Init URL: $init_url\n";
    
    my $init_request = HTTP::Request->new(
        POST => $init_url,
        [
            'Authorization' => "Bearer $access_token",
            'Content-Type' => 'application/json',
        ],
        encode_json({
            name => $object_name,
        })
    );
    
#    print STDERR "Request headers:\n";
#    $init_request->headers->scan(sub { print STDERR "  $_[0]: $_[1]\n" });
#    print STDERR "Request body: " . $init_request->content . "\n";

    my $init_response = $ua->request($init_request);
    
#    print STDERR "Response status: " . $init_response->code . "\n";
#    print STDERR "Response body: " . $init_response->content . "\n";

    unless ($init_response->is_success) {
        die "Failed to initiate resumable upload: " . $init_response->status_line;
    }
    
    my $session_uri = $init_response->header('Location');
    
    unless ($session_uri) {
        die "No session URI returned from initiation";
    }
    
#    print "Resumable upload session created: $session_uri\n";
    
    # Step 2: Upload file in chunks
    open my $fh, '<:raw', $source_file or die "Can't open $source_file: $!";
    
    my $file_size = -s $source_file;
    my $bytes_uploaded = 0;
    my $buffer;
    
    while (my $bytes_read = sysread($fh, $buffer, $chunk_size)) {
        my $start = $bytes_uploaded;
        my $end = $bytes_uploaded + $bytes_read - 1;
        
        my $upload_request = HTTP::Request->new(
            PUT => $session_uri,
            [
                'Content-Length' => $bytes_read,
                'Content-Range' => "bytes $start-$end/$file_size",
            ],
            $buffer
        );
        
        my $upload_response = $ua->request($upload_request);
        
        if ($upload_response->code == 308) {
            # Resume incomplete - continue
            print "Uploaded bytes $start-$end / $file_size\n";
        } elsif ($upload_response->is_success) {
            # Upload complete
            print "Upload completed successfully!\n";
            close $fh;
            return decode_json($upload_response->content);
        } else {
            close $fh;
            die "Upload failed at byte $start: " . $upload_response->status_line;
        }
        
        $bytes_uploaded += $bytes_read;
    }
    
    close $fh;
    return undef;

}

sub download_file {

    my ( $self, $filename, $save_dir ) = @_;

    unless ( -e $save_dir ) {
        die "Save directory does not exist: $save_dir";
    }

    $self->_refresh_access_token();

    my $access_token = $self->{'access_token'}->{'access_token'};

    my $url = 'https://storage.googleapis.com/storage/v1/b/' . $self->{'bucket_name'};
    $url .= '/o/' . $filename . '?alt=media';

    my $ua = LWP::UserAgent->new();
    my $r  = HTTP::Request->new(
        'GET' => $url,
        [ 'Authorization' => 'Bearer ' . $access_token ],
    );
    my $response = $ua->request( $r, "$save_dir/$filename" );

    if ( $response->is_success() ) {
        return 1;
    }
    else {
        die 'Download Failed: ' . $response->status_line();
    }
}

sub remove_file {

    my ( $self, $filename ) = @_;

    unless ($filename) {
        die "missing parameter to remove_file";
    }

    $self->_refresh_access_token();

    my $access_token = $self->{'access_token'}->{'access_token'};
    my $url          = 'https://storage.googleapis.com/storage/v1/b/';
    $url .= $self->{'bucket_name'} . '/o/' . $filename;

    my $ua = LWP::UserAgent->new( timeout => 10 );

    $ua->default_header( 'Authorization' => 'Bearer ' . $access_token );

    my $response = $ua->delete($url);

    if ( $response->is_success() ) {
        return 1;
    }
    else {
        die 'remove_file Failed: ' . $response->status_line();
    }
}

1;

__END__

=head1 NAME

Google::Cloud::Storage::Bucket

=head1 SYNOPSIS

    # Instantiate access to an existing bucket on the Google Cloud Storage platform
    # using Service Account authentication

    my $bucket = Google::Cloud::Storage::Bucket->new( {
        'private_key_file' => '/etc/private/gcs.key',
        'client_email' => 'email@test.com',
        'bucket_name' => 'my_bucket'}
    );

    # OR using OAuth2 user authentication

    my $bucket = Google::Cloud::Storage::Bucket->new( {
        'client_id' => 'your_client_id',
        'client_secret' => 'your_client_secret',
        'refresh_token' => 'your_refresh_token',
        'bucket_name' => 'my_bucket'}
    );

    # Get a JSON object containing the list of files

    my $files = $bucket->list_files;

=head1 DESCRIPTION

L<GOOGLE::CLOUD::STORAGE::BUCKET> allows you to perform file operations on objects
stored in Google Cloud Storage buckets.  It supports two authentication methods:

=over

=item * Service Account authentication (recommended for server-to-server)
L<Using OAuth 2.0 for Server to Server Applications|https://developers.google.com/identity/protocols/oauth2/service-account>

=item * OAuth2 user authentication (for user-delegated access)

=back

Under the hood, this module is using the Google Cloud Storage JSON API
L<Cloud Storage JSON API|https://cloud.google.com/storage/docs/json_api>


=head1 CONSTRUCTOR

=head2 new

    # Service Account authentication
    my $bucket = Google::Cloud::Storage::Bucket->new(
        { 'private_key_file' => '/etc/private/gcs.key',
          'client_email' => 'email@test.com',
          'bucket_name' => 'my_bucket'}
    );

    # OAuth2 user authentication
    my $bucket = Google::Cloud::Storage::Bucket->new(
        { 'client_id' => 'your_client_id',
          'client_secret' => 'your_client_secret',
          'refresh_token' => 'your_refresh_token',
          'bucket_name' => 'my_bucket'}
    );

This method creates a new bucket object and authenticates to the Google Cloud Storage platform.  The
object will store and manage an access token.  The token has a 60 minute TTL.  The object will handle
refreshing the token automatically.

=head2 Required Parameters

=head3 For Service Account Authentication:

=over

=item C<client_email>

The client email for the Google Service Account.

=item C<private_key>

The private key as a string (can be extracted from the service account JSON file), OR

=item C<private_key_file>

Path to a file containing the private key.

=item C<bucket_name>

The name of the Google Service Bucket

=back

=head3 For OAuth2 User Authentication:

=over

=item C<client_id>

The OAuth2 Client ID.

=item C<client_secret>

The OAuth2 Client Secret.

=item C<refresh_token>

The OAuth2 Refresh Token.

=item C<bucket_name>

The name of the Google Service Bucket

=back

=head1 METHODS

=over

=item C<list_files>

    my $files = $bucket->list_files;

Returns a hash containing the list of files in the bucket

=item C<upload_file>

    my $ret = $bucket->upload_file('/path/filename');

Uploads a file to the bucket.  

The method currently does not do file chunking or checksum validation

=item C<download_file>

    my $ret = $bucket->download_file('filename', '/destination/path');

Downloads a file from the bucket to local storage.

=item C<remove_file>

    my $ret = $bucket->remove_file('starman.log');

Removes a file from the Google bucket.  Be careful with this.  Once a file is deleted it cannot be restored.

=back

=head1 AUTHOR

Aaron Stone <aaron@mydestination.us>

=cut
