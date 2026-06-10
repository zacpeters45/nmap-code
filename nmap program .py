# zac peters
# 17/05/2026
# Assignment Assessment 4 - Part 4

# This program scans a target host for open, closed and filtered ports
# using nmap. It also grabs banners from open ports and displays
# geolocation details of the IP address.

print('Port Scanner program developed by: Zac Peters')

# import required libraries
import socket                # used for converting hostnames to IP addresses
import nmap                  # used for port scanning
import geoip2.database       # used for geolocation lookup


# function to grab banner from open ports

def bannerread(ip, port):
    try:
        # create socket connection to reach out to the target port
        sockets = socket.socket()
        sockets.settimeout(2)   # timeout after 2 seconds
        sockets.connect((ip, port))

        # receive banner from service
        banner = sockets.recv(1024).decode().strip()
        sockets.close()

        return banner
    except:
        # return if no banner is available
        return "No banner"

def main():

    # loop until user enters a valid hostname
    while True:
        host = input("Enter the host name: ")

        # basic check to see if the string is empty
        if len(host) < 1:
            print("Host name cannot be empty.\n")
        else:
            try:
                print("Checking host, please wait...")

                # convert hostname to IP address
                ip_address = socket.gethostbyname(host)

                # break the loop now that we have a valid target
                break
            except:
                print("Invalid host address. Try again.\n")

    # check to make sure we have a valid IP
    if ip_address == "":
        print("Exiting program.")
        return

    # print the target IP so we know where we're pointing the scanner
    print(f"\nIP Address: {ip_address}")
    print("Scanning ports between 1 - 1024")

    # create an object called nmap
    scanner = nmap.PortScanner()

    # scanning the default range (1-1024)
    scanner.scan(hosts=ip_address, ports='1-1024')

    # prepping the terminal for the results
    print("\nPORT SCANNING RESULTS:")
    print(f"Host: {ip_address}\n")

    # making sure the host is actually active on the network
    if ip_address in scanner.all_hosts():

        # look specifically for TCP protocol data
        if 'tcp' in scanner[ip_address]:

            # sorting the ports so the list is nice and readable
            for port in sorted(scanner[ip_address]['tcp']):

                #  the current state and service name for this port
                state = scanner[ip_address]['tcp'][port]['state']
                name = scanner[ip_address]['tcp'][port]['name']

                # defining the state meanings for internal logic
                if state == 'open':
                    explanation = "OPEN – service is accepting connections"
                elif state == 'closed':
                    explanation = "CLOSED – no service listening"
                elif state == 'filtered':
                    explanation = "FILTERED – blocked by firewall"
                else:
                    explanation = "UNKNOWN state"


                if state == 'open':
                    # grab the banner if the port is open
                    banner = bannerread(ip_address, port)
                    print(f"Port: {port} | Status: {state.upper()} | Service: {name} | {banner}")
                else:
                    # just showing standard status for closed/filtered ports
                    print(f"Port: {port} | Status: {state.upper()} | Service: {name}")

        else:
            #no TCP ports were detected
            print("No TCP ports found.")
    else:
        # alert if the scan couldn't reach the target at all
        print("Host not responding.")

    # GEO LOCATION SECTION
    try:
        # access the geo database to map the IP location
        reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        location_data = reader.city(ip_address)
        # dumping all the location details we pulled from the database
        print("\nLOCATION DETAILS:")
        print(f"Continent Name: {location_data.continent.name}")
        print(f"Continent Code: {location_data.continent.code}")
        print(f"Country Name:   {location_data.country.name}")
        print(f"Country Code:   {location_data.country.iso_code}")
        print(f"City Name:      {location_data.city.name}")
        print(f"Postal Code:    {location_data.postal.code}")
        print(f"Time Zone:      {location_data.location.time_zone}")
        # closing the database reader to be clean
        reader.close()

    except:
        # handle cases where the db is missing or the IP is local/unknown
        print("\nGeolocation data not available.")


# end main
main()
