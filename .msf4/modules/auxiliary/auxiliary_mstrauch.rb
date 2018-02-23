require 'socket'
require 'msf/core'
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
	rhost = datastore['RHOST']
	rport = datastore['RPORT']
	if rhost == nil or rport == nil
            print_error("rhost or rport is not properly configured")
            return
        end
        s = TCPSocket.open(rhost, rport)
	begin
            line = s.gets
	rescue Exception => e
	    print_status("#{rhost}:#{rport} is not vulnerable.")
	    puts "No vulnerability detected"
	end
        if line =~ /BockServe 2.0a/
	    s.send("view",0)
	    2.times{s.gets}
	    
	    s.send("yes",0)
	    2.times{s.gets}
	    s.send("print \"hi\"",0)
	    line = s.gets
	    puts line
	    if line =~ /(python -c)|(hi)/
    	        print_status("#{rhost}:#{rport} is vulnerable.")
	    else
		print_status("not vulnerable")
	    end
        else 
            print_status("#{rhost}:#{rport} is not vulnerable.")
        end
	s.close()	
    end
end
