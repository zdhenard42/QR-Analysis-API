// src/index.js
var src_default = {
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      const headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-Requested-With"
      };
      return new Response(null, { status: 204, headers });
    }
    if (request.method === "POST" && url.pathname.startsWith("/decode-qr")) {
      const response = await fetch("https://api.qrserver.com/v1/read-qr-code/", {
        method: "POST",
        headers: request.headers,
        body: request.body
      });
      const jsonResponse = await response.json();
      const qrUrl = jsonResponse?.[0]?.symbol?.[0]?.data;
      console.log(qrUrl);
      if (!qrUrl) {
        return new Response("Failed to decode QR", { status: 400 });
      }
      const encodedQrData = await encodeURIComponent(qrUrl);
      console.log(encodedQrData);
      const redirectUrl = `https://api.redirect-checker.net/?url=${encodedQrData}&timeout=15&maxhops=20&meta-refresh=1&format=json&more=1`;
      const redirectResponse = await fetch(redirectUrl);
      const redirectData = await redirectResponse.json();
      const finalHostIP = await redirectData.data[redirectData.data.length - 1]?.response?.info?.primary_ip;
      const finalHost = await redirectData.data[redirectData.data.length - 1]?.request?.info?.url;
      if (finalHostIP == void 0) {
        return new Response("URL is invalid", { status: 400 });
      }
      console.log(finalHostIP);
      console.log("This is", finalHost);
      const shodanIP = `https://api.shodan.io/shodan/host/${finalHostIP}?&minify=True&key=<SHODAN KEY HERE>`;
      const shodanIPResponse = await fetch(shodanIP);
      const shodanIPData = await shodanIPResponse.json();
      console.log(shodanIPData);
      const abuseIPDBURL = `https://api.abuseipdb.com/api/v2/check?ipAddress=${finalHostIP}&maxAgeInDays=364`;
      const abuseipdbResponse = await fetch(abuseIPDBURL, {
        headers: {
          "Key": "<ABUSEIPDB KEY HERE>"
        }
      });
      const abuseipdbData = await abuseipdbResponse.json();
      console.log("ABUSEIPDB DATA", abuseipdbData);
      const VirusTotalURL = `https://www.virustotal.com/api/v3/ip_addresses/${finalHostIP}`;
      const VirusTotalResponse = await fetch(VirusTotalURL, {
        headers: {
          "x-apikey": "<VIRUSTOTAL KEY HERE>"
        }
      });
      const VirusTotalData = await VirusTotalResponse.json();
      const bodyData = new URLSearchParams();
      bodyData.append("url", finalHost);
      const URLHaus = await fetch(`https://urlhaus-api.abuse.ch/v1/url`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: bodyData
      });
      const URLHausResponse = await URLHaus.json();
      const customData = {
        qrUrl,
        finalHost,
        HostIP: finalHostIP,
        abuseConfidenceScore: abuseipdbData.data.abuseConfidenceScore,
        abuseDomain: abuseipdbData.data.domain,
        abuseISP: abuseipdbData.data.isp,
        abuseUsageType: abuseipdbData.data.usageType,
        abuseTotalReports: abuseipdbData.data.totalReports,
        abuseIsTor: abuseipdbData.data.isTor,
        shodanASN: shodanIPData?.asn,
        shodanPorts: shodanIPData?.ports,
        shodanCountry: shodanIPData?.country_name,
        shodanOS: shodanIPData?.os,
        VirusTotalNetwork: VirusTotalData.data.attributes.network,
        virusTotalAnalysis: VirusTotalData.data.attributes.last_analysis_stats,
        virusTotalWhoIs: VirusTotalData.data.attributes.whois,
        URLHausOffline: URLHausResponse.url_status,
        URLHausThreat: URLHausResponse.threat,
        URLHausReference: URLHausResponse.urlhaus_reference,
        URLHausTags: URLHausResponse.tags
      };
      const headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      };
      return new Response(JSON.stringify(customData), { status: 200, headers });
    }
    return new Response("Not Found", { status: 404 });
  }
};
export {
  src_default as default
};
//# sourceMappingURL=index.js.map
