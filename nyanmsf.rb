##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Post-Exploitation module for nyan.mbr',
        'Description'   => %q{
          Overwrite the master boot record of a Linux or Windows system with nice kitties.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Chase Lucas - @calucas27' ],
        'Platform'      => [ 'win', 'linux', 'osx', 'unix', 'bsd' ],
        'SessionTypes'  => [ 'meterpreter', 'shell' ]
    ))
  end

  def run
    # Main method
  end

end
