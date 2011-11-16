<?xml version='1.0'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<!-- <xsl:import href="/usr/share/sgml/docbook/xsl-stylesheets/manpages/docbook.xsl"/> -->
<xsl:import href="manpages/docbook.xsl"/>

<!-- A Pre-processor for converting Nmap refguide to proper nroff -->

<!-- Kill <web> tag which doesn't apply to nroff man page output -->
<xsl:template match="web">
<!-- do nothing -->
</xsl:template>

<!-- Kill continuation, which belongs to paper book rendering -->
<xsl:template match="continuation">
</xsl:template>

<!-- But we do want to include the inverse -->
<xsl:template match="notweb">
  <xsl:apply-templates />
</xsl:template>

<!-- We should include the contents of <notbook> tags too -->
<xsl:template match="notbook">
  <xsl:apply-templates />
</xsl:template>

<!-- Include parts that belong in a standalone man page. -->
<xsl:template match="man">
  <xsl:apply-templates />
</xsl:template>

<!-- Ignore parts that don't belong in a standalone man page (like when
it's a chapter in a book). -->
<xsl:template match="notman">
<!-- do nothing -->
</xsl:template>


<!-- Kill <pubdate> tag which apparently causes man page problems. -->
<xsl:template match="pubdate">
<!-- do nothing -->
</xsl:template>

<!-- let's try killing article and artheader, which the translated man pages
      have (I don't remember why they do). -->
<xsl:template match="article">
    <xsl:apply-templates/>
</xsl:template>
<xsl:template match="artheader">
    <xsl:apply-templates/>
</xsl:template>

</xsl:stylesheet>
