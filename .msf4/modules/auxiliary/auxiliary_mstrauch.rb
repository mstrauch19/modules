require 'socket'

class MetasploitModule < Msf::Auxiliary

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
    def run_host(ip)
        s = TCPSocket.new rhost rport

        if rhost is None or rport is None
            print_error("rhost or rport is not properly configured")
            return
        end
	begin
            line = s.gets
	rescue Exception => e
	    print_status("#{rhost}:#{rport} is vulnerable.")
	    puts "No vulnerability detected"
	end
        if line =~ /BockServe 2.0a/
            print_status("#{rhost}:#{rport} is vulnerable.")
        else 
            print_status("#{rhost}:#{rport} is not vulnerable.")
	    print "not vulnerable"
        end 
    end
end
