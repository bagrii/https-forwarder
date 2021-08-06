# HTTPS Forwarder
HTTPS Forwarder lets you run multiple "virtual" servers on the same IP address, using the [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication) as a way to distinguish between multiple hosted domains.
 
## Build
`go build -o https-forwarder`
 
## Usage
`https-forwarder` accept two command line arguments:
- `verbose`: boolean value to indicate level of logging.
- `apps-file`: specify configuration file that contains all information of where to forward requests for particular host names. Template configuration file can be found in the root source code folder, named: `applications.ini`.  

Sample usage:
`./https-forwarder --verbose=true --apps-file applications.ini`
