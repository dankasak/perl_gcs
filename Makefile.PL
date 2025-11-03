use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'Google::Cloud::Storage::Bucket',
    VERSION_FROM      => 'Google/Cloud/Storage/Bucket.pm',
    ABSTRACT          => 'Google Cloud Storage API client with OAuth2 and Service Account support',
    AUTHOR            => 'Aaron Stone <aaron@mydestination.us>',
    LICENSE           => 'perl',
    MIN_PERL_VERSION  => '5.010',
    PREREQ_PM         => {
        'JSON'              => 0,
        'JSON::WebToken'    => 0,
        'LWP::UserAgent'    => 0,
        'File::Basename'    => 0,
    },
    TEST_REQUIRES     => {
        'Test::More'        => 0,
    },
    META_MERGE        => {
        'meta-spec' => { version => 2 },
        resources   => {
            repository => {
                type => 'git',
                url  => 'https://github.com/yourusername/perl_gcs.git',
                web  => 'https://github.com/yourusername/perl_gcs',
            },
        },
    },
);
