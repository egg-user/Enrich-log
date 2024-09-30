const express = require('express');
const fs = require('fs');
const path = require('path');
const { getPrefixDescription } = require('./netbox'); 
const axios = require('axios'); 
const syslog = require('syslog-client');

const app = express();
const PORT = 3000;

const apiServers = [
    'http://localhost:5000',
    'http://localhost:5001',
    'http://localhost:5002'
];

let currentServerIndex = 0;

function getNextServer() {
    const server = apiServers[currentServerIndex];
    currentServerIndex = (currentServerIndex + 1) % apiServers.length;
    return server;
}

async function fallbackIpLookup(ipAddress) {
    try {
        const apiUrl = `${getNextServer()}/iplookup?ip=${ipAddress}`;
        const response = await axios.get(apiUrl);
        return response.data;
    } catch (error) {
        console.error(`Error fetching fallback IP lookup for ${ipAddress}:`, error);
        return { description: 'No data available from fallback' };
    }
}

const syslogClient1 = syslog.createClient("10.255.50.10", {
    port: 514,   
    transport: syslog.Transport.Udp  
});


const syslogClient2 = syslog.createClient("10.255.50.9", {
    port: 514,  
    transport: syslog.Transport.Udp  
});

app.use(express.urlencoded({ extended: true }));

function extractASName(description) {
    if (typeof description !== 'string') {
        console.error('Description is not a string:', description);
        return 'Unknown';
    }
    const match = description.match(/^(.*?)(?:\s*\(AS\d+\))?\s*(?:,\s*.*)?$/);
    return match ? match[1].trim() : 'Unknown';
}

function extractASDomain(description) {
    if (typeof description !== 'string') {
        console.error('Description is not a string:', description);
        return 'Unknown';
    }
    const match = description.match(/,\s*(\S+)\s*$/);
    return match ? match[1].trim() : 'Unknown';
}

function safeReplace(value) {
    if (typeof value === 'string') {
        return value.replace(/ /g, '.');
    } else {
        console.error('Value is not a string:', value);
        return '';
    }
}

const invalidCountries = ['Reversed']
async function getCountryCoordinates(country) {
    if (invalidCountries.includes(country)){
        console.log(`Country '${country}' is not valid. Returning default coordinates.`);
        return { Latitude: '-7.983908', Longitude: '112.621391' };
    }
    try {
        const apiUrl = `http://localhost:5050/geo/${country}`;
        const response = await axios.get(apiUrl);
        return response.data; 
    } catch (error) {
        return { Latitude: '-7.983908', Longitude: '112.621391' };
    }
}


app.post('/webhook', async (req, res) => {
    const data = req.body;
    const message = Object.keys(data)[0];

    const [timestamp, source_ip, destination_ip, source_country, destination_country, severity, threat_type, action] = message.split('|');

    let sourceDescription = await getPrefixDescription(source_ip);
    let destinationDescription = await getPrefixDescription(destination_ip);

    if (!sourceDescription.prefix) {
        console.log(`Source IP ${source_ip} not found in NetBox, calling fallback API...`);
        sourceDescription = await fallbackIpLookup(source_ip);
    }

    if (!destinationDescription.prefix) {
        console.log(`Destination IP ${destination_ip} not found in NetBox, calling fallback API...`);
        destinationDescription = await fallbackIpLookup(destination_ip);
    }

    const sourceCoordinates = await getCountryCoordinates(source_country);
    const destinationCoordinates = await getCountryCoordinates(destination_country);

    const extractASN = (description) => {
        if (typeof description !== 'string') {
            console.error('Description is not a string: ', description);
            return 'Unknown';
        }
        const asnMatch = description.match(/\bAS(\d+)\b/);
        return asnMatch ? asnMatch[0] : 'Unknown';
    }

    const sourceASName = extractASName(sourceDescription.description);
    const destinationASName = extractASName(destinationDescription.description);

    const sourceASDomain = extractASDomain(sourceDescription.description)
    const destinationASDomain = extractASDomain(destinationDescription.description)

    const sourceASN = extractASN(sourceDescription.description)
    const destinationASN = extractASN(destinationDescription.description)


    const jsonData = {
        "ips-firewall":"alert",
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_country": source_country,
        "destination_country": destination_country,
        "severity": severity,
        "threat_type": threat_type,
        "action": action,
        "source_asn": sourceASN,
        "source_as_name": sourceASName,
        "source_as_domain": sourceASDomain,
        "source_description": sourceDescription.description,
        "destination_asn": destinationASN,
        "destination_as_name": destinationASName,
        "destination_as_domain": destinationASDomain,
        "destination_description": destinationDescription.description,
        "source_country_latitude": sourceCoordinates.Latitude,
        "source_country_longitude": sourceCoordinates.Longitude,
        "destination_country_latitude": destinationCoordinates.Latitude,
        "destination_country_longitude": destinationCoordinates.Longitude
    };

    const filePath = path.join('/var/log/firewall/alerts.json');

    fs.appendFile(filePath, JSON.stringify(jsonData) + '\n', (err) => {
        if (err) {
            console.error('Error appending log data:', err);
            return res.status(500).send('Error appending log data');
        }
        console.log('Log data appended to:', filePath);

        const syslogMessage = `ips-firewall timestamp=${jsonData.timestamp} source_country=${safeReplace(jsonData.source_country)} destination_country=${safeReplace(jsonData.destination_country)} source_ip=${jsonData.source_ip} destination_ip=${jsonData.destination_ip} Threat_detected=${jsonData.threat_type} Severity=${jsonData.severity} action=${jsonData.action} source_asn=${jsonData.source_asn} destination_asn=${jsonData.destination_asn} source_as_name=${safeReplace(jsonData.source_as_name)} destination_as_name=${safeReplace(jsonData.destination_as_name)} source_as_domain=${jsonData.source_as_domain} destination_as_domain=${jsonData.destination_as_domain} source_description=${safeReplace(jsonData.source_description)} destination_description=${safeReplace(jsonData.destination_description)} source_lat=${jsonData.source_country_latitude} source_long=${jsonData.source_country_longitude} destination_lat=${jsonData.destination_country_latitude} destination_long=${jsonData.destination_country_longitude}`;
        syslogClient1.log(syslogMessage, { facility: syslog.Facility.Local0, severity: syslog.Severity.Warning }, (error) => {
            if (error) {
                console.error('Error sending syslog message to 10.255.50.10:', error);
            } else {
                console.log('Syslog message sent successfully');
            }
        });

        syslogClient2.log(syslogMessage, { facility: syslog.Facility.Local0, severity: syslog.Severity.Warning }, (error) => {
            if (error) {
                console.error('Error sending syslog message to 10.255.50.9:', error);
            } else {
                console.log('Syslog message sent successfully');
            }
        });

        res.send('Log received and formatted for Wazuh');
    });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
