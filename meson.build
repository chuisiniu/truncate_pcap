project('truncate_pcap', 'c')

sources = ['main.c']

pcap = dependency('pcap', required: true)

if 'darwin' == build_machine.system() and 'aarch64' == build_machine.cpu()
    link_args = []
else
    link_args = ['-static']
endif

executable('tp',
           sources,
	   link_args: link_args,
	   dependencies: pcap)