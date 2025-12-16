project('blob-splitter', 'c',
    version: '0.1.0',
    default_options: ['c_std=c11']
)

executable('shamir-test',
    sources: ['src/shamir-test.c', 'shamir/shamir.c', 'util/random.c'],
    include_directories: include_directories('.'),
    install: false,
)
executable('ascon-test',
    sources: ['src/ascon-test.c', 'util/ascon.c', 'util/random.c'],
    include_directories: include_directories('.'),
    install: false,
)

executable('blob-splitter',
    sources: ['src/blob-splitter.c', 'shamir/shamir.c', 'util/random.c'],
    include_directories: include_directories('.'),
    install: true,
)