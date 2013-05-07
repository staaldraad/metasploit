#
# $Id: history.rb 1 2013-02-26 15:00:00Z etienne@sensepost.com $
#

module Msf

###
#
# This plugin adds a history command to metasploit.  
#
# $Revision: 1 $
###
class Plugin::History < Msf::Plugin

	class ConsoleCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher

		def name
			"History"
		end

		def commands
			{
				"history" => "A simple command added by the history plugin"
			}
		end

		#
		# This method handles the history command.
		#
		def cmd_history(*args)

			num_display = 10
			if args.length > 0
				arg0 = args[0]
				if arg0[0] == '!' or arg0[0] == 33
					multi_cmd = arg0.index('-')
					if multi_cmd != nil and multi_cmd > 0
						r_start = Integer(arg0[1,multi_cmd-1])
						r_end = Integer(arg0[multi_cmd+1,arg0.length-1])
						print_status("Running multiple commands")
		
						for i in r_start..r_end
   							
   							cm = Readline::HISTORY[i]
   							if cm != nil
	   							print_status("#{i} #{cm}")
								driver.run_single(cm)
							else
								print_error("We went out of range there... stopping exec\nWrong index for #{i}")
								return nil
							end
						end
						
					else	
						hist_num = Integer(arg0[1,arg0.length-1])
						cm = Readline::HISTORY[hist_num]
						print_status ("#{cm}")
						driver.run_single(cm)
					end
					return nil
				else
					num_display = Integer(arg0)
				end
			end

			num = Readline::HISTORY.length - ($hist_last_saved)-1

			if num < num_display
				num_display = num
			end

            tmprc = ""
            tmp = ""
            num_display.times { |x|
            	    tmp = Readline::HISTORY[$hist_last_saved + x]
                    tmprc <<  tmp
                    print_line ("#{$hist_last_saved+x} #{tmp}")
            }

            if tmprc.length == 0
                    print_error("No history to display")
            end


		end

		def cmd_history_help()
			print_line ("Usage: history [num|cmd]")
			print_line ("\nnum: the number of history elements to show (default 10) ")
			print_line ("cmd: ! followed by the history number of the command to execute")
			print_line ("cmd: !a-b will execute all the commands in the range a..b")
			print_line ("\nExample: history 3")
			print_line ("342 help")
			print_line ("343 use exploit/windows/smb/psexec")
			print_line ("344 show options")
			print_line ("\nExample: history !343 -- this will execute the command 'use exploit/windows/smb/psexec'")
			print_line ("Example: history !342-344 -- this will execute the commands 342, 343 and 344")
			print_line ("")
		end
	end

	
	def initialize(framework, opts)
		super

		add_console_dispatcher(ConsoleCommandDispatcher)

		num = Readline::HISTORY.length
		$hist_last_saved = num
		print_status("History plugin loaded.")
		
	end

	def cleanup

		remove_console_dispatcher('History')
		
	end

	def name
		"history"
	end

	def desc
		"Adds history command to msfconsole.\nUsage: history [num|!num[-num]]"
	end

end
end
