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
        register_options(
                [
                    OptString.new('USER',    [true, 'Target User for NetSessionEnum', '']),
                    OptString.new('VERBOSE',    [false, 'Display failed logins/missing hosts', 'false']),
                ], self.class)
    end

    # Run Method for when run command is issued
    def run
        
        if datastore['USER']
            @user = datastore['USER']
            domain = getdomain()
            @sessions = 0
            @verbose = false
            if datastore['VERBOSE'] == 'true'
                print_status ("Verbose output enabled")
                @verbose = true
            end

            if not domain.empty?
                print_status ("Using domain: #{domain}")
                print_status ("Getting list of domain hosts")
                hostname_list = get_domain_hosts()
                
                count = 1

                if hostname_list != nil
                    len = hostname_list.length
                    print_status ("#{len} hosts found")
                    print_status ("Searching for sessions, user: #{@user}")

                    hostname_list.each do |x|
                        getSessions(x,@user)
                        count = count + 1
                        if count%10 == 0
                            print_status ("#{count} of #{len} hosts checked")
                        end
                    end
                end

                if @sessions == 0
                    print_status("No sessions found")
                else
                    print_status("#{@sessions} identified")
                end

            end
        end
    end

    # From mubix enum_sessions.rb (https://github.com/mubix/stuff/blob/master/metasploit/enum_sessions.rb)
    def read_session_struct(startmem,count)
        base = 0
        netsessions = []
        mem = client.railgun.memread(startmem, 16*count)
        count.times{|i|
            x = {}
            cnameptr = mem[(base + 0),4].unpack("V*")[0]
            usernameptr = mem[(base + 4),4].unpack("V*")[0]
            x[:usetime] = mem[(base + 8),4].unpack("V*")[0]
            x[:idletime] = mem[(base + 12),4].unpack("V*")[0]
            x[:cname] = client.railgun.memread(cnameptr,255).split("\0\0")[0].split("\0").join
            x[:username] = client.railgun.memread(usernameptr,255).split("\0\0")[0].split("\0").join
            netsessions << x
            base = base + 16
        }
        return netsessions
    end

    # Modified from mubix enum_sessions.rb (https://github.com/mubix/stuff/blob/master/metasploit/enum_sessions.rb)
    def getSessions(hostname,username)

        client.railgun.add_function('netapi32', 'NetSessionEnum', 'DWORD',[
        ['PWCHAR','servername','in'],
        ['PWCHAR','UncClientName','in'],
        ['PWCHAR','username','in'],
        ['DWORD','level','in'],
        ['PDWORD','bufptr','out'],
        ['DWORD','prefmaxlen','in'],
        ['PDWORD','entriesread','out'],
        ['PDWORD','totalentries','out'],
        ['PDWORD','resume_handle','inout']
        ])


        buffersize = 500
        result = client.railgun.netapi32.NetSessionEnum(hostname,nil,username,10,4,buffersize,4,4,nil)
        if result['return'] == 5
            if @verbose == true
                print_error("Access Denied when trying to access host: #{hostname}")
            end
            return nil
        elsif result['return'] == 53
            if @verbose  == true
                print_error("Host not found or did not respond: #{hostname}")
            end
            return nil
        elsif result['return'] == 123
            if @verbose == true
                print_error("Invalid host: #{hostname}")
            end
            return nil
        elsif result['return'] == 0
            if @verbose == true
                print_status("#{hostname} Session identified")
            end
        elsif result['return'] == 2221 #username not found
            return nil
        else
            if result['return'] != 234
                #print_status("Missed this one.. Recieved error code: #{result['return']}")
                return nil
            end
        end

        #print_status("Finding the right buffersize...")
        while result['return'] == 234
            #print_status("Tested #{buffersize}, got #{result['entriesread']} of #{result['totalentries']}")
            buffersize = buffersize + 500
            result = client.railgun.netapi32.NetSessionEnum(hostname,nil,username,10,4,buffersize,4,4,nil)
        end

        netsessions = read_session_struct(result['bufptr'],result['totalentries'])
        if netsessions.size > 0
            netsessions.each do |x|
                #addr = gethost(hostname)
                print_good("#{username} is logged in at #{hostname}  and has been idle for #{x[:idletime]} seconds")
                @sessions = @sessions + 1
            end
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
        #NetServerEnum(nil,100,4,buffersize,4,4,servertype,nil,nil)
        result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,servertype,nil,nil)
        
        if result['return'] == 5
            if @verbose == true
                print_error("Access Denied when trying to enum hosts.")
            end
            return nil
        elsif result['return'] == 6118
            if @verbose == true
                print_error("No Browser servers found.")
            end
            return nil
        elsif result['return'] == 50
            if @verbose  == true
                print_error("Request not supported.")
            end
            return nil
        elsif result['return'] == 2184
            if @verbose == true
                print_error("Service not installed.")
            end
            return nil
        elsif result['return'] == 0
            if @verbose == true
                print_status("Great success")
            end
        elsif result['return'] == 87 #username not found
            print_error ("invalid parameter")
            return nil
        else
            if result['return'] != 234
                #print_status("Missed this one.. Recieved error code: #{result['return']}")
                return nil
            end
        end

        #figure out right buffersize
        while result['return'] == 234
            buffersize = buffersize + 500
            #print_good("Buffer++")
            result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,servertype,nil,nil)
        end

        hostnames = []
        print_good ("Got a list of hosts... Parsing... this could take a while...")
        netservers = read_server_struct(result['bufptr'],result['totalentries'])
        if netservers.size > 0
            netservers.each do |x|
                #print_good("server #{x}")
                hostnames << x[:name]
            end
        end
        return hostnames #for now we are just returning a list of hostnames.
                         #should probably change this to process hosts as they are returned
    end

    def read_server_struct(startmem,count) 
        base = 0
        netservers = []
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

    # Gets the Domain Name -- originally from enum_domain.rb -- Don't really need this, more informational
    def getdomain()
        domain = ""
        begin
            subkey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History"
            v_name = "DCName"
            domain_dc = registry_getvaldata(subkey, v_name)
            dom_info =  domain_dc.split('.')
            domain = dom_info[1].upcase
        rescue
            print_error("This host is not part of a domain.")
        end
        return domain
    end

end