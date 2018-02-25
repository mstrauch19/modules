require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
    def initialize
        super(
            'Name'           => 'BockServer 2.0a Exploiter',
            'Description'    => 'This module can exploit BockServer 2.0a, creating a meterpreter shell.',
	    'Platform' => ['python'],
	    'Arch' => ARCH_PYTHON,
	    'Targets' => [['automatic', {}],],
	    'DefaultTarget' => 0,
      'SessionTypes' => ['meterpreter', 'shell']
      )
    end
    
    def run
    
    end
end
