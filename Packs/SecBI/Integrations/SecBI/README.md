<p>
The SecBI solution is designed for a transformation of the security operation, enabled by automation of the detection and investigation, to the response, including remediation and prevention policy enforcements on all integrated appliances.

This integration was integrated and tested with version 3.2.x of SecBI
</p>
<h2>Use Cases</h2>
<ul>
<li><code>secbi-get-incidents-list</code>: Get all of the incidents related to a specific hunting query (Elasticsearch), return (if matched) the list of IDs of relevant incidents inside the SecBI system.</li>
<li><code>secbi-get-incident</code>: Get all of the details of a specific incident by its ID (could be used as the next step after GetIncidents), returns all the details of the specific incident, including all involved users, destinations and the detailed detections made by the SecBI system.</li>
<li><code>secbi-get-incident-by-host</code>: Get all of the details of a specific incident by searching for a specific destination (could be used for IOC match or as a broader scope detection request), returns all the details of the specific incident involving the specific host, including all involved users, and all destinations (possibly implicating other destinations aside from the one in the request),  and the detailed detections made by the SecBI system.</li>
</ul><h2>Detailed Description</h2>
<p>With attacks growing exponentially in volume and complexity, organizations face an almost insurmountable challenge to implement effective security programs at a time when security resources are severely limited. They struggle with inadequate time, funds, skillsets and headcount.</p>
<p>SecBI makes detection and response quick, accurate and simple, with its proprietary underlined technology, AI-based Autonomous Investigation™, mimicking an expert analyst at machine speed.</p>
<p>SecBI’s Autonomous Investigation amplifies the alert prioritization and incident investigation skills of security analyst teams, allowing them to efficiently prioritize alerts from other systems, and easily investigate and triage incidents through analytics-driven visibility.</p>
<p>SecBI builds behavioral profiles for users and hosts by applying Autonomous Investigation techniques, including supervised and unsupervised machine learning, on data from the network and security infrastructure, enriched with threat intelligence.</p>
<p>The security insights generated by SecBI analytics are oriented around a user or host and make it easy for automated response, as well as allowing analysts to conduct their incident investigation efforts and the hunting for the unknown threats.</p>
<p><strong>The SecBI solution is designed for a transformation of the security operation, enabled by automation of the detection and investigation, to the response, including remediation and prevention policy enforcements on all integrated appliances.</strong></p>
<h2>Configure SecBI on Cortex XSOAR</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for SecBI.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>SecBI API URL (e.g. https://demisto.secbi.com)</strong></li>
   <li><strong>SecBI API key</strong></li>
   <li><strong>Use system proxy settings</strong></li>
   <li><strong>Trust any certificate (not secure)</strong></li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>
<h2>Commands</h2>
<p>
  You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li><a href="#secbi-get-incidents-list" target="_self">SecBI Get All Incident IDs: secbi-get-incidents-list</a></li>
  <li><a href="#secbi-get-incident" target="_self">Get a specific SecBI Incident by SecBI Incident ID: secbi-get-incident</a></li>
  <li><a href="#secbi-get-incident-by-host" target="_self">Get a specific SecBI Incident by Host: secbi-get-incident-by-host</a></li>
</ol>
<h3 id="secbi-get-incidents-list">1. secbi-get-incidents-list</h3>
<hr>
<p>SecBI Get All Incident IDs</p>
<h5>Base Command</h5>
<p>
  <code>secbi-get-incidents-list</code>
</p>

<h5>Required Permissions</h5>
<p>No special permissions required.</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>query</td>
      <td>The Query by which to filter the Incident IDs</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>limit</td>
      <td>Limit amount of IDs to return (<code>-1</code>) for all. Default is <code>100</code></td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>SecBI.IncidentsList</td>
      <td>String</td>
      <td>SecBI Incident IDs List</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!secbi-get-incidents-list query="severity:[60 TO 100]" limit="3"</code>
</p>

<h5>Human Readable Output</h5>
<p>
### List of SecBI Incidents
|ID|
|---|
| 7899b0ff-810b-4df4-a0e3-806557aecc2e |
| 3de12111-3b09-45b7-8ac8-6ab88be48b52 |
| 0e83beac-b374-4f89-b2ab-ecc851414ec9 |
</p>

<h3 id="secbi-get-incident">2. secbi-get-incident</h3>
<hr>
<p>Get a specific SecBI Incident by SecBI Incident ID</p>
<h5>Base Command</h5>
<p>
  <code>secbi-get-incident</code>
</p>

<h5>Required Permissions</h5>
<p>No special permissions required.</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>incident_id</td>
      <td>SecBI incident ID</td>
      <td>Required</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>SecBI.Incident.ID</td>
      <td>String</td>
      <td>SecBI incident ID</td>
    </tr>
    <tr>
      <td>SecBI.Incident.Host</td>
      <td>String</td>
      <td>SecBI incident host names</td>
    </tr>
    <tr>
      <td>SecBI.Incident.Identity</td>
      <td>String</td>
      <td>SecBI incident identities</td>
    </tr>
    <tr>
      <td>SecBI.Incident.InternalIp</td>
      <td>String</td>
      <td>SecBI incident client internal IP addresses</td>
    </tr>
    <tr>
      <td>SecBI.Incident.SIp</td>
      <td>String</td>
      <td>SecBI incident client IP addresses</td>
    </tr>
    <tr>
      <td>SecBI.Incident.FirstAppearance</td>
      <td>Date</td>
      <td>SecBI incident first appearance of data</td>
    </tr>
    <tr>
      <td>SecBI.Incident.LastAppearance</td>
      <td>Date</td>
      <td>SecBI incident last appearance of data</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!secbi-get-incident incident_id=7899b0ff-810b-4df4-a0e3-806557aecc2e</code>
</p>

<h5>Human Readable Output</h5>
<p>
### SecBI incident ID "7899b0ff-810b-4df4-a0e3-806557aecc2e"
|FirstAppearance|Host|ID|Identity|InternalIp|LastAppearance|SIp|
|---|---|---|---|---|---|---|
| 2017-07-31 06:46:14 | pix.crp.education,<br>solutions.sante-corps-esprit.com,<br>tracking.notizie.it,<br>editions.biosante-editions.fr,<br>www.nikon.fr,<br>www.mailant.it,<br>static.biosante-editions.com,<br>static.pubfac.com,<br>moodle.ead-online.be,<br>img1.gtv.digimondo.net,<br>static.snieditions.com,<br>www.trgmedia.it,<br>ws.atomikad.com,<br>www.ead-online.be,<br>www.smooto.com,<br>www.cronacaeugubina.it,<br>www.elfri.be | 7899b0ff-810b-4df4-a0e3-806557aecc2e | joe@acme.com | 172.23.152.25,<br>172.23.152.26 | 2017-08-04 08:22:43 | 141.101.61.31,<br>37.187.151.239,<br>52.85.180.13,<br>52.85.180.203,<br>151.80.18.159,<br>94.23.64.3,<br>134.213.72.175,<br>46.37.22.52,<br>95.85.13.99,<br>46.37.22.123,<br>54.72.0.177,<br>23.253.140.198,<br>0.0.0.0,<br>176.62.160.38,<br>52.85.180.177 |
</p>

<h3 id="secbi-get-incident-by-host">3. secbi-get-incident-by-host</h3>
<hr>
<p>Get a specific SecBI Incident by Host</p>
<h5>Base Command</h5>
<p>
  <code>secbi-get-incident-by-host</code>
</p>

<h5>Required Permissions</h5>
<p>No special permissions required.</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>host</td>
      <td>The host by which to get a SecBI Incident</td>
      <td>Required</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>SecBI.Incident.ID</td>
      <td>String</td>
      <td>SecBI incident ID</td>
    </tr>
    <tr>
      <td>SecBI.Incident.Host</td>
      <td>String</td>
      <td>SecBI incident host names</td>
    </tr>
    <tr>
      <td>SecBI.Incident.Identity</td>
      <td>String</td>
      <td>SecBI incident identities</td>
    </tr>
    <tr>
      <td>SecBI.Incident.InternalIp</td>
      <td>String</td>
      <td>SecBI incident client internal IP addresses</td>
    </tr>
    <tr>
      <td>SecBI.Incident.SIp</td>
      <td>String</td>
      <td>SecBI incident client IP addresses</td>
    </tr>
    <tr>
      <td>SecBI.Incident.FirstAppearance</td>
      <td>Date</td>
      <td>SecBI incident first appearance of data</td>
    </tr>
    <tr>
      <td>SecBI.Incident.LastAppearance</td>
      <td>Date</td>
      <td>SecBI incident last appearance of data</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!secbi-get-incident-by-host host=www.smooto.com</code>
</p>

<h5>Human Readable Output</h5>
<p>
### SecBI incident by host "www.smooto.com"
|FirstAppearance|Host|ID|Identity|InternalIp|LastAppearance|SIp|
|---|---|---|---|---|---|---|
| 2017-07-31 06:46:14 | pix.crp.education,<br>solutions.sante-corps-esprit.com,<br>tracking.notizie.it,<br>editions.biosante-editions.fr,<br>www.nikon.fr,<br>www.mailant.it,<br>static.biosante-editions.com,<br>static.pubfac.com,<br>moodle.ead-online.be,<br>img1.gtv.digimondo.net,<br>static.snieditions.com,<br>www.trgmedia.it,<br>ws.atomikad.com,<br>www.ead-online.be,<br>www.smooto.com,<br>www.cronacaeugubina.it,<br>www.elfri.be | 7899b0ff-810b-4df4-a0e3-806557aecc2e | joe@acme.com | 172.23.152.25,<br>172.23.152.26 | 2017-08-04 08:22:43 | 141.101.61.31,<br>37.187.151.239,<br>52.85.180.13,<br>52.85.180.203,<br>151.80.18.159,<br>94.23.64.3,<br>134.213.72.175,<br>46.37.22.52,<br>95.85.13.99,<br>46.37.22.123,<br>54.72.0.177,<br>23.253.140.198,<br>0.0.0.0,<br>176.62.160.38,<br>52.85.180.177 |
</p>
