def list_files()
  require 'find'
  exclude = [
#    'C:/Windows/Temp/',
#    'C:/Windows/Prefetch/',
#    'C:/Windows/Installer/',
#    'C:/Windows/WinSxS/',
#    'C:/Windows/Logs/',
#    'C:/Windows/servicing/',
#    'C:/Windows/ServiceProfiles/NetworkService/AppData/Local/Microsoft/Windows/DeliveryOptimization/Logs/',
#    'C:/Windows/ServiceProfiles/NetworkService/AppData/Local/Microsoft/Windows/DeliveryOptimization/Cache/',
#    'C:/Windows/SoftwareDistribution/DataStore/Logs/',
#    'C:/Windows/System32/wbem/Performance/',
#    'c:/windows/System32/LogFiles/'
  ].each { |e| e.downcase! }
  return Find.find('c:/windows/').reject { |f| f.downcase.start_with?(*exclude) }
end


