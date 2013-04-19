require 'msf/core'
require 'rex'

# Multi platform requiere
require 'msf/core/post/common'
require 'msf/core/post/file'

require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post

    include Msf::Post::Common
    include Msf::Post::File

    include Msf::Post::Windows::Registry

    def initialize(info={})
        super( update_info( info,
                'Name'         => 'Windows Gather Enumerate Domain Users',
                'Description'  => %q{
                        This module will enumerate computers included in the primary Domain. And attempt
                        to list all locations the targeted user has sessions on'
                },
                'License'      => MSF_LICENSE,
                'Author'       => [ 'Etienne Stalmans <etienne[at]sensepost.com>'],
                'Platform'     => [ 'win'],
                'SessionTypes' => [ 'meterpreter' ]
            ))
        print_status("Init")
        register_options(
                [
                    
                ], self.class)
    end

    # Run Method for when run command is issued
    def run
        names = get_domain_hosts()
        names.each do |x|
            print_status("#{x}")
        end
    end

def get_domain_hosts()
        #use railgun and NetServerEnum
        client.railgun.add_function('netapi32', 'NetServerEnum', 'DWORD',[
        ['PWCHAR','servername','in'],
        ['DWORD','level','in'],
        ['PDWORD','bufptr','out'],
        ['DWORD','prefmaxlen','in'],
        ['PDWORD','entriesread','out'],
        ['PDWORD','totalentries','out'],
        ['DWORD','servertype','in'],
        ['PWCHAR','domain','in'],
        ['PWCHAR','resume_handle','inout']
        ])


        buffersize = 500
        servertype = 3 #workstations and servers

        #NetServerEnum(servername,level,bufptr,prefmaxlen,entriesread,totalentries,servertype,domain,resume_handle)
        result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,servertype,nil,nil)
        print_status("#{result['return']}")
        if result['return'] == 5
            if @verbose == true
                print_error("Access Denied when trying to enum hosts")
            end
            return nil
        elsif result['return'] == 50
            if @verbose  == true
                print_error("Request not supported")
            end
            return nil
        elsif result['return'] == 2184
            if @verbose == true
                print_error("Service not installed")
            end
            return nil
        elsif result['return'] == 0
            if @verbose == true
                print_status("Great success")
            end
        elsif result['return'] == 87 #username not found
            print_error ("invalid parameter")
            return nil
        elsif result['return'] != 234
            print_status("Missed this one.. Recieved error code: #{result['return']}")
            return nil
        end

        #figure out right buffersize
        while result['return'] == 234
            buffersize = buffersize + 500
            result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,servertype,nil,nil)
        end

        hostnames = []
        netservers = read_server_struct(result['bufptr'],result['totalentries'])
        if netservers.size > 0
            netservers.each do |x|
                print_good("server #{x}")
                hostnames << x[:name]
            end
        end
        return hostnames #for now we are just returning a list of hostnames.
                         #should probably change this to process hosts as they are returned
    end

    def read_server_struct(startmem,count) 
        base = 0
        netservers = []
        print_status("parsing results")
        mem = client.railgun.memread(startmem, 8*count)
        
        count.times{|i|
            x = {}
            x[:version]=version = mem[(base + 0),4].unpack("V*")[0]
            nameptr = mem[(base + 4),4].unpack("V*")[0]
            x[:name] = client.railgun.memread(nameptr,255).split("\0\0")[0].split("\0").join
            base = base + 8
            netservers << x
        }
        return netservers
    end

end