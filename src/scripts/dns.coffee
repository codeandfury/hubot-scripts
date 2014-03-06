# Description:
#   Lookup Domain DNS Info using viewdns.info public and free API (App Key Required)
#
# Configuration:
#   HUBOT_VIEWDNS_KEY
#
# Commands:
#   hubot dns lookup <domainname> - Return A record for <domainname>
#   hubot dns record <record> <domainname> = Return values for <record>
#   hubot dns propagation <domainname> - Returns global dns entries
#   hubot dns ping <domainname> - Test how long a response from remote system takes to reach the server
#   hubot dns abuse <domainname> - Return the abuse contact address for a domain name
#   hubot dns firewall <china/iran> <domainname> - Checks whether a site is blocked by the Great Firewall of China (china) or Iran firewall (iran)
#   hubot dns freemail <domainname> - Find out if a domain provides free email addresses
#   hubot dns location <ip address> - Display geographic information
#   hubot dns portscan <ip address/domainname> - Test if common ports are open on a server
#   hubot dns reverse <ip address/domainname> - Show all domains hosted on a server
#
# Author:
#   Phil Hess

module.exports = (robot) ->
  robot.hear /dns lookup (\S*)/i, (msg) ->
    msg.send "Thinking..."
    domain = escape(msg.match[1])
    key = process.env.HUBOT_VIEWDNS_KEY;
    msg.http("http://pro.viewdns.info/dnsrecord/?domain=#{domain}&recordtype=A&apikey=#{key}&output=json")
      .headers(Accept: 'application/json')
      .get() (err, res, body) ->
        switch res.statusCode
          when 401
            msg.send "You need to authenticate by setting the HUBOT_VIEWDNS_KEY environment variable"
          when 200
            response = JSON.parse body
            if not response.response.records[0]
              msg.send "No A Records found. Perhaps it has a cname record?"
            else
              for item in response.response.records
                do (item) ->
                  msg.send item.data
          else
            msg.send "Unable to process your request. Status: #{res.statusCode}"

  robot.hear /dns record (\S*) (\S*)/i, (msg) ->
    msg.send "Thinking..."
    recordType = escape(msg.match[1])
    domain = escape(msg.match[2])
    key = process.env.HUBOT_VIEWDNS_KEY;
    msg.http("http://pro.viewdns.info/dnsrecord/?domain=#{domain}&recordtype=#{recordType}&apikey=#{key}&output=json")
      .headers(Accept: 'application/json')
      .get() (err, res, body) ->
        switch res.statusCode
          when 401
            msg.send "You need to authenticate by setting the HUBOT_VIEWDNS_KEY environment variable"
          when 200
            response = JSON.parse body
            if not response.response.records[0]
              msg.send "No #{recordType} Records found."
            else
              for item in response.response.records
                do (item) ->
                  if not item.priority
                    msg.send "#{item.name} | #{item.type} | #{item.ttl} | #{item.data}"
                  else
                    msg.send "#{item.name} | #{item.type} | #{item.ttl} | Priority: #{item.priority} | #{item.data}"
          else
            msg.send "Unable to process your request. Status: #{res.statusCode}"

  robot.hear /dns propagation (.*)/i, (msg) ->
    msg.send "Thinking..."
    domain = escape(msg.match[1])
    key = process.env.HUBOT_VIEWDNS_KEY;
    msg.http("http://pro.viewdns.info/propagation/?domain=#{domain}&apikey=#{key}&output=json")
      .headers(Accept: 'application/json')
      .get() (err, res, body) ->
        switch res.statusCode
          when 401
            msg.send "You need to authenticate by setting the HUBOT_VIEWDNS_KEY environment variable"
          when 200
            response = JSON.parse body
            if not response.response.server[0]
              msg.send "Lookup Failed"
            else
              for item in response.response.server
                do (item) ->
                  msg.send "#{item.resultstatus} | #{item.resultvalue} | #{item.location}"
          else
            msg.send "Unable to process your request. Status: #{res.statusCode}"

  robot.hear /dns ping (.*)/i, (msg) ->
    msg.send "Thinking..."
    domain = escape(msg.match[1])
    key = process.env.HUBOT_VIEWDNS_KEY;
    msg.http("http://pro.viewdns.info/ping/?host=#{domain}&apikey=#{key}&output=json")
      .headers(Accept: 'application/json')
      .get() (err, res, body) ->
        switch res.statusCode
          when 401
            msg.send "You need to authenticate by setting the HUBOT_VIEWDNS_KEY environment variable"
          when 200
            response = JSON.parse body
            if not response.response.replys[0]
              msg.send "Lookup Failed"
            else
              for item in response.response.replys
                do (item) ->
                  msg.send item.rtt
          else
            msg.send "Unable to process your request. Status: #{res.statusCode}"

  robot.hear /dns abuse (.*)/i, (msg) ->
    msg.send "Thinking..."
    domain = escape(msg.match[1])
    key = process.env.HUBOT_VIEWDNS_KEY;
    msg.http("http://pro.viewdns.info/abuselookup/?domain=#{domain}&apikey=#{key}&output=json")
      .headers(Accept: 'application/json')
      .get() (err, res, body) ->
        switch res.statusCode
          when 401
            msg.send "You need to authenticate by setting the HUBOT_VIEWDNS_KEY environment variable"
          when 200
            response = JSON.parse body
            if not response.response
              msg.send "Lookup Failed"
            else
              msg.send response.response.abusecontact
          else
            msg.send "Unable to process your request. Status: #{res.statusCode}"

  robot.hear /dns firewall (\S*) (\S*)/i, (msg) ->
    msg.send "Thinking..."
    domain = escape(msg.match[2])
    isChina = if (escape(msg.match[1])) == "china" then true else false
    service = if isChina then "chinesefirewall" else "iranfirewall"
    domainKey = if isChina then "domain" else "siteurl"
    key = process.env.HUBOT_VIEWDNS_KEY;
    msg.http("http://pro.viewdns.info/#{service}/?#{domainKey}=#{domain}&apikey=#{key}&output=json")
      .headers(Accept: 'application/json')
      .get() (err, res, body) ->
        switch res.statusCode
          when 401
            msg.send "You need to authenticate by setting the HUBOT_VIEWDNS_KEY environment variable"
          when 200
            response = JSON.parse body
            if isChina
              if not response.v2response.dnsresults.description
                msg.send "Lookup Failed"
              else
                msg.send response.v2response.dnsresults.description
            else
              if not response.response
                msg.send "Lookup Failed"
              else
                msg.send response.response.result
          else
            msg.send "Unable to process your request. Status: #{res.statusCode}"

  robot.hear /dns freemail (.*)/i, (msg) ->
    msg.send "Thinking..."
    domain = escape(msg.match[1])
    key = process.env.HUBOT_VIEWDNS_KEY;
    msg.http("http://pro.viewdns.info/freeemail/?domain=#{domain}&apikey=#{key}&output=json")
      .headers(Accept: 'application/json')
      .get() (err, res, body) ->
        switch res.statusCode
          when 401
            msg.send "You need to authenticate by setting the HUBOT_VIEWDNS_KEY environment variable"
          when 200
            if not response.response
              msg.send "Lookup Failed"
            else
              msg.send response.response.result
          else
            msg.send "Unable to process your request. Status: #{res.statusCode}"

  robot.hear /dns location (.*)/i, (msg) ->
    msg.send "Thinking..."
    ip = escape(msg.match[1])
    key = process.env.HUBOT_VIEWDNS_KEY;
    msg.http("http://pro.viewdns.info/iplocation/?ip=#{ip}&apikey=#{key}&output=json")
      .headers(Accept: 'application/json')
      .get() (err, res, body) ->
        switch res.statusCode
          when 401
            msg.send "You need to authenticate by setting the HUBOT_VIEWDNS_KEY environment variable"
          when 200
            response = JSON.parse body
            if not response.response
              msg.send "Lookup Failed"
            else
              msg.send "#{response.response.city}, #{response.response.region_name} #{response.response.country_name} | #{response.response.latitude}, #{response.response.longitude}"
          else
            msg.send "Unable to process your request. Status: #{res.statusCode}"

  robot.hear /dns portscan (.*)/i, (msg) ->
    msg.send "Thinking..."
    domain = escape(msg.match[1])
    key = process.env.HUBOT_VIEWDNS_KEY;
    msg.http("http://pro.viewdns.info/portscan/?host=#{domain}&apikey=#{key}&output=json")
      .headers(Accept: 'application/json')
      .get() (err, res, body) ->
        switch res.statusCode
          when 401
            msg.send "You need to authenticate by setting the HUBOT_VIEWDNS_KEY environment variable"
          when 200
            response = JSON.parse body
            if not response.response.port[0]
              msg.send "Lookup Failed"
            else
              for item in response.response.port
                do (item) ->
                  msg.send "#{item.service} | #{item.number} | #{item.status}"
          else
            msg.send "Unable to process your request. Status: #{res.statusCode}"

  robot.hear /dns reverse (.*)/i, (msg) ->
    msg.send "Thinking..."
    domain = escape(msg.match[1])
    key = process.env.HUBOT_VIEWDNS_KEY;
    msg.http("http://pro.viewdns.info/reverseip/?host=#{domain}&apikey=#{key}&output=json")
      .headers(Accept: 'application/json')
      .get() (err, res, body) ->
        switch res.statusCode
          when 401
            msg.send "You need to authenticate by setting the HUBOT_VIEWDNS_KEY environment variable"
          when 200
            response = JSON.parse body
            if not response.response.domains[0]
              msg.send "Lookup Failed"
            else
              for item in response.response.domains
                do (item) ->
                  msg.send item.name
          else
            msg.send "Unable to process your request. Status: #{res.statusCode}"