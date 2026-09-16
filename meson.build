project('sysreader', 'c', license : 'MIT', meson_version : '>=1.00', version : '0.1.0')

r2_plugdir = run_command('r2', '-H', 'R2_USER_PLUGINS', check: true).stdout().strip()

sources = [
  'src/sysreader.c',
  'src/iterate_args.c'
]
inc_dir = include_directories('include')
lib = library('sysreader', sources,
        include_directories : inc_dir,
	dependencies : [
		dependency('r_core'),
		dependency('r_util'),
		dependency('r_syscall'),
	],
	install_dir: r2_plugdir,
	install: true
)

install_data('data/syscalls.json',
	install_dir: r2_plugdir
)
