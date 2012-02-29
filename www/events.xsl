<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <xsl:template match="/">
    <html>
      <head>
        <meta http-equiv="refresh" content="10" />
      </head>
      <body>
        <table border="1">
          <tr bgcolor="#9acd32">
            <th>Priority</th>
            <th>Timestamp</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Message</th>
            <th>Classification</th>
          </tr>
          <xsl:for-each select="EVENTS/EVENT">
            <tr>
              <td>
                <xsl:value-of select="PRIORITY"/>
              </td>
              <td>
                <xsl:value-of select="TIME"/>
              </td>
              <td>
                [<xsl:value-of select="IPSRC"/>]:<xsl:value-of select="SPORT"/>
              </td>
              <td>
                [<xsl:value-of select="IPDST"/>]:<xsl:value-of select="DPORT"/>
              </td>
              <td>
                <xsl:value-of select="MSG"/>
              </td>
              <td>
                <xsl:value-of select="CLASSIFICATION"/>
              </td>
            </tr>
          </xsl:for-each>
        </table>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
