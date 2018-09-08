description = [[
Spiders a site's images looking for interesting exif data embedded in
.jpg files. Displays the make and model of the camera, the date the photo was
taken, and the embedded geotag information.
]]

---
-- @usage
-- nmap --script http-exif-spider -p80,443 <host>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-exif-spider:
-- |   http://www.javaop.com/Nationalmuseum.jpg
-- |     Make: Canon
-- |     Model: Canon PowerShot S100\xB4
-- |     Date: 2003:03:29 13:35:40
-- |   http://www.javaop.com/topleft.jpg
-- |_    GPS: 49.941250,-97.206189 - https://maps.google.com/maps?q=49.94125,-97.20618863493
--
-- @args http-exif-spider.url the url to start spidering. This is a URL
-- relative to the scanned host eg. /default.html (default: /)

author = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive"}

local shortport = require 'shortport'
local stdnse = require 'stdnse'
local httpspider = require 'httpspider'
local string = require 'string'
local table = require 'table'

-- These definitions are copied/pasted/reformatted from the jhead-2.96 sourcecode
-- (the code is effectively public domain, but credit where credit's due!)
TAG_INTEROP_INDEX          = 0x0001
TAG_INTEROP_VERSION        = 0x0002
TAG_IMAGE_WIDTH            = 0x0100
TAG_IMAGE_LENGTH           = 0x0101
TAG_BITS_PER_SAMPLE        = 0x0102
TAG_COMPRESSION            = 0x0103
TAG_PHOTOMETRIC_INTERP     = 0x0106
TAG_FILL_ORDER             = 0x010A
TAG_DOCUMENT_NAME          = 0x010D
TAG_IMAGE_DESCRIPTION      = 0x010E
TAG_MAKE                   = 0x010F
TAG_MODEL                  = 0x0110
TAG_SRIP_OFFSET            = 0x0111
TAG_ORIENTATION            = 0x0112
TAG_SAMPLES_PER_PIXEL      = 0x0115
TAG_ROWS_PER_STRIP         = 0x0116
TAG_STRIP_BYTE_COUNTS      = 0x0117
TAG_X_RESOLUTION           = 0x011A
TAG_Y_RESOLUTION           = 0x011B
TAG_PLANAR_CONFIGURATION   = 0x011C
TAG_RESOLUTION_UNIT        = 0x0128
TAG_TRANSFER_FUNCTION      = 0x012D
TAG_SOFTWARE               = 0x0131
TAG_DATETIME               = 0x0132
TAG_ARTIST                 = 0x013B
TAG_WHITE_POINT            = 0x013E
TAG_PRIMARY_CHROMATICITIES = 0x013F
TAG_TRANSFER_RANGE         = 0x0156
TAG_JPEG_PROC              = 0x0200
TAG_THUMBNAIL_OFFSET       = 0x0201
TAG_THUMBNAIL_LENGTH       = 0x0202
TAG_Y_CB_CR_COEFFICIENTS   = 0x0211
TAG_Y_CB_CR_SUB_SAMPLING   = 0x0212
TAG_Y_CB_CR_POSITIONING    = 0x0213
TAG_REFERENCE_BLACK_WHITE  = 0x0214
TAG_RELATED_IMAGE_WIDTH    = 0x1001
TAG_RELATED_IMAGE_LENGTH   = 0x1002
TAG_CFA_REPEAT_PATTERN_DIM = 0x828D
TAG_CFA_PATTERN1           = 0x828E
TAG_BATTERY_LEVEL          = 0x828F
TAG_COPYRIGHT              = 0x8298
TAG_EXPOSURETIME           = 0x829A
TAG_FNUMBER                = 0x829D
TAG_IPTC_NAA               = 0x83BB
TAG_EXIF_OFFSET            = 0x8769
TAG_INTER_COLOR_PROFILE    = 0x8773
TAG_EXPOSURE_PROGRAM       = 0x8822
TAG_SPECTRAL_SENSITIVITY   = 0x8824
TAG_GPSINFO                = 0x8825
TAG_ISO_EQUIVALENT         = 0x8827
TAG_OECF                   = 0x8828
TAG_EXIF_VERSION           = 0x9000
TAG_DATETIME_ORIGINAL      = 0x9003
TAG_DATETIME_DIGITIZED     = 0x9004
TAG_COMPONENTS_CONFIG      = 0x9101
TAG_CPRS_BITS_PER_PIXEL    = 0x9102
TAG_SHUTTERSPEED           = 0x9201
TAG_APERTURE               = 0x9202
TAG_BRIGHTNESS_VALUE       = 0x9203
TAG_EXPOSURE_BIAS          = 0x9204
TAG_MAXAPERTURE            = 0x9205
TAG_SUBJECT_DISTANCE       = 0x9206
TAG_METERING_MODE          = 0x9207
TAG_LIGHT_SOURCE           = 0x9208
TAG_FLASH                  = 0x9209
TAG_FOCALLENGTH            = 0x920A
TAG_SUBJECTAREA            = 0x9214
TAG_MAKER_NOTE             = 0x927C
TAG_USERCOMMENT            = 0x9286
TAG_SUBSEC_TIME            = 0x9290
TAG_SUBSEC_TIME_ORIG       = 0x9291
TAG_SUBSEC_TIME_DIG        = 0x9292
TAG_WINXP_TITLE            = 0x9c9b
TAG_WINXP_COMMENT          = 0x9c9c
TAG_WINXP_AUTHOR           = 0x9c9d
TAG_WINXP_KEYWORDS         = 0x9c9e
TAG_WINXP_SUBJECT          = 0x9c9f
TAG_FLASH_PIX_VERSION      = 0xA000
TAG_COLOR_SPACE            = 0xA001
TAG_PIXEL_X_DIMENSION      = 0xA002
TAG_PIXEL_Y_DIMENSION      = 0xA003
TAG_RELATED_AUDIO_FILE     = 0xA004
TAG_INTEROP_OFFSET         = 0xA005
TAG_FLASH_ENERGY           = 0xA20B
TAG_SPATIAL_FREQ_RESP      = 0xA20C
TAG_FOCAL_PLANE_XRES       = 0xA20E
TAG_FOCAL_PLANE_YRES       = 0xA20F
TAG_FOCAL_PLANE_UNITS      = 0xA210
TAG_SUBJECT_LOCATION       = 0xA214
TAG_EXPOSURE_INDEX         = 0xA215
TAG_SENSING_METHOD         = 0xA217
TAG_FILE_SOURCE            = 0xA300
TAG_SCENE_TYPE             = 0xA301
TAG_CFA_PATTERN            = 0xA302
TAG_CUSTOM_RENDERED        = 0xA401
TAG_EXPOSURE_MODE          = 0xA402
TAG_WHITEBALANCE           = 0xA403
TAG_DIGITALZOOMRATIO       = 0xA404
TAG_FOCALLENGTH_35MM       = 0xA405
TAG_SCENE_CAPTURE_TYPE     = 0xA406
TAG_GAIN_CONTROL           = 0xA407
TAG_CONTRAST               = 0xA408
TAG_SATURATION             = 0xA409
TAG_SHARPNESS              = 0xA40A
TAG_DISTANCE_RANGE         = 0xA40C
TAG_IMAGE_UNIQUE_ID        = 0xA420

TagTable = {}
TagTable[TAG_INTEROP_INDEX]         = "InteropIndex"
TagTable[TAG_INTEROP_VERSION]       = "InteropVersion"
TagTable[TAG_IMAGE_WIDTH]           = "ImageWidth"
TagTable[TAG_IMAGE_LENGTH]          = "ImageLength"
TagTable[TAG_BITS_PER_SAMPLE]       = "BitsPerSample"
TagTable[TAG_COMPRESSION]           = "Compression"
TagTable[TAG_PHOTOMETRIC_INTERP]    = "PhotometricInterpretation"
TagTable[TAG_FILL_ORDER]            = "FillOrder"
TagTable[TAG_DOCUMENT_NAME]         = "DocumentName"
TagTable[TAG_IMAGE_DESCRIPTION]     = "ImageDescription"
TagTable[TAG_MAKE]                  = "Make"
TagTable[TAG_MODEL]                 = "Model"
TagTable[TAG_SRIP_OFFSET]           = "StripOffsets"
TagTable[TAG_ORIENTATION]           = "Orientation"
TagTable[TAG_SAMPLES_PER_PIXEL]     = "SamplesPerPixel"
TagTable[TAG_ROWS_PER_STRIP]        = "RowsPerStrip"
TagTable[TAG_STRIP_BYTE_COUNTS]     = "StripByteCounts"
TagTable[TAG_X_RESOLUTION]          = "XResolution"
TagTable[TAG_Y_RESOLUTION]          = "YResolution"
TagTable[TAG_PLANAR_CONFIGURATION]  = "PlanarConfiguration"
TagTable[TAG_RESOLUTION_UNIT]       = "ResolutionUnit"
TagTable[TAG_TRANSFER_FUNCTION]     = "TransferFunction"
TagTable[TAG_SOFTWARE]              = "Software"
TagTable[TAG_DATETIME]              = "DateTime"
TagTable[TAG_ARTIST]                = "Artist"
TagTable[TAG_WHITE_POINT]           = "WhitePoint"
TagTable[TAG_PRIMARY_CHROMATICITIES]= "PrimaryChromaticities"
TagTable[TAG_TRANSFER_RANGE]        = "TransferRange"
TagTable[TAG_JPEG_PROC]             = "JPEGProc"
TagTable[TAG_THUMBNAIL_OFFSET]      = "ThumbnailOffset"
TagTable[TAG_THUMBNAIL_LENGTH]      = "ThumbnailLength"
TagTable[TAG_Y_CB_CR_COEFFICIENTS]  = "YCbCrCoefficients"
TagTable[TAG_Y_CB_CR_SUB_SAMPLING]  = "YCbCrSubSampling"
TagTable[TAG_Y_CB_CR_POSITIONING]   = "YCbCrPositioning"
TagTable[TAG_REFERENCE_BLACK_WHITE] = "ReferenceBlackWhite"
TagTable[TAG_RELATED_IMAGE_WIDTH]   = "RelatedImageWidth"
TagTable[TAG_RELATED_IMAGE_LENGTH]  = "RelatedImageLength"
TagTable[TAG_CFA_REPEAT_PATTERN_DIM]= "CFARepeatPatternDim"
TagTable[TAG_CFA_PATTERN1]          = "CFAPattern"
TagTable[TAG_BATTERY_LEVEL]         = "BatteryLevel"
TagTable[TAG_COPYRIGHT]             = "Copyright"
TagTable[TAG_EXPOSURETIME]          = "ExposureTime"
TagTable[TAG_FNUMBER]               = "FNumber"
TagTable[TAG_IPTC_NAA]              = "IPTC/NAA"
TagTable[TAG_EXIF_OFFSET]           = "ExifOffset"
TagTable[TAG_INTER_COLOR_PROFILE]   = "InterColorProfile"
TagTable[TAG_EXPOSURE_PROGRAM]      = "ExposureProgram"
TagTable[TAG_SPECTRAL_SENSITIVITY]  = "SpectralSensitivity"
TagTable[TAG_GPSINFO]               = "GPS Dir offset"
TagTable[TAG_ISO_EQUIVALENT]        = "ISOSpeedRatings"
TagTable[TAG_OECF]                  = "OECF"
TagTable[TAG_EXIF_VERSION]          = "ExifVersion"
TagTable[TAG_DATETIME_ORIGINAL]     = "DateTimeOriginal"
TagTable[TAG_DATETIME_DIGITIZED]    = "DateTimeDigitized"
TagTable[TAG_COMPONENTS_CONFIG]     = "ComponentsConfiguration"
TagTable[TAG_CPRS_BITS_PER_PIXEL]   = "CompressedBitsPerPixel"
TagTable[TAG_SHUTTERSPEED]          = "ShutterSpeedValue"
TagTable[TAG_APERTURE]              = "ApertureValue"
TagTable[TAG_BRIGHTNESS_VALUE]      = "BrightnessValue"
TagTable[TAG_EXPOSURE_BIAS]         = "ExposureBiasValue"
TagTable[TAG_MAXAPERTURE]           = "MaxApertureValue"
TagTable[TAG_SUBJECT_DISTANCE]      = "SubjectDistance"
TagTable[TAG_METERING_MODE]         = "MeteringMode"
TagTable[TAG_LIGHT_SOURCE]          = "LightSource"
TagTable[TAG_FLASH]                 = "Flash"
TagTable[TAG_FOCALLENGTH]           = "FocalLength"
TagTable[TAG_MAKER_NOTE]            = "MakerNote"
TagTable[TAG_USERCOMMENT]           = "UserComment"
TagTable[TAG_SUBSEC_TIME]           = "SubSecTime"
TagTable[TAG_SUBSEC_TIME_ORIG]      = "SubSecTimeOriginal"
TagTable[TAG_SUBSEC_TIME_DIG]       = "SubSecTimeDigitized"
TagTable[TAG_WINXP_TITLE]           = "Windows-XP Title"
TagTable[TAG_WINXP_COMMENT]         = "Windows-XP comment"
TagTable[TAG_WINXP_AUTHOR]          = "Windows-XP author"
TagTable[TAG_WINXP_KEYWORDS]        = "Windows-XP keywords"
TagTable[TAG_WINXP_SUBJECT]         = "Windows-XP subject"
TagTable[TAG_FLASH_PIX_VERSION]     = "FlashPixVersion"
TagTable[TAG_COLOR_SPACE]           = "ColorSpace"
TagTable[TAG_PIXEL_X_DIMENSION]     = "ExifImageWidth"
TagTable[TAG_PIXEL_Y_DIMENSION]     = "ExifImageLength"
TagTable[TAG_RELATED_AUDIO_FILE]    = "RelatedAudioFile"
TagTable[TAG_INTEROP_OFFSET]        = "InteroperabilityOffset"
TagTable[TAG_FLASH_ENERGY]          = "FlashEnergy"
TagTable[TAG_SPATIAL_FREQ_RESP]     = "SpatialFrequencyResponse"
TagTable[TAG_FOCAL_PLANE_XRES]      = "FocalPlaneXResolution"
TagTable[TAG_FOCAL_PLANE_YRES]      = "FocalPlaneYResolution"
TagTable[TAG_FOCAL_PLANE_UNITS]     = "FocalPlaneResolutionUnit"
TagTable[TAG_SUBJECT_LOCATION]      = "SubjectLocation"
TagTable[TAG_EXPOSURE_INDEX]        = "ExposureIndex"
TagTable[TAG_SENSING_METHOD]        = "SensingMethod"
TagTable[TAG_FILE_SOURCE]           = "FileSource"
TagTable[TAG_SCENE_TYPE]            = "SceneType"
TagTable[TAG_CFA_PATTERN]           = "CFA Pattern"
TagTable[TAG_CUSTOM_RENDERED]       = "CustomRendered"
TagTable[TAG_EXPOSURE_MODE]         = "ExposureMode"
TagTable[TAG_WHITEBALANCE]          = "WhiteBalance"
TagTable[TAG_DIGITALZOOMRATIO]      = "DigitalZoomRatio"
TagTable[TAG_FOCALLENGTH_35MM]      = "FocalLengthIn35mmFilm"
TagTable[TAG_SUBJECTAREA]           = "SubjectArea"
TagTable[TAG_SCENE_CAPTURE_TYPE]    = "SceneCaptureType"
TagTable[TAG_GAIN_CONTROL]          = "GainControl"
TagTable[TAG_CONTRAST]              = "Contrast"
TagTable[TAG_SATURATION]            = "Saturation"
TagTable[TAG_SHARPNESS]             = "Sharpness"
TagTable[TAG_DISTANCE_RANGE]        = "SubjectDistanceRange"
TagTable[TAG_IMAGE_UNIQUE_ID]       = "ImageUniqueId"

GPS_TAG_VERSIONID        = 0X00
GPS_TAG_LATITUDEREF      = 0X01
GPS_TAG_LATITUDE         = 0X02
GPS_TAG_LONGITUDEREF     = 0X03
GPS_TAG_LONGITUDE        = 0X04
GPS_TAG_ALTITUDEREF      = 0X05
GPS_TAG_ALTITUDE         = 0X06
GPS_TAG_TIMESTAMP        = 0X07
GPS_TAG_SATELLITES       = 0X08
GPS_TAG_STATUS           = 0X09
GPS_TAG_MEASUREMODE      = 0X0A
GPS_TAG_DOP              = 0X0B
GPS_TAG_SPEEDREF         = 0X0C
GPS_TAG_SPEED            = 0X0D
GPS_TAG_TRACKREF         = 0X0E
GPS_TAG_TRACK            = 0X0F
GPS_TAG_IMGDIRECTIONREF  = 0X10
GPS_TAG_IMGDIRECTION     = 0X11
GPS_TAG_MAPDATUM         = 0X12
GPS_TAG_DESTLATITUDEREF  = 0X13
GPS_TAG_DESTLATITUDE     = 0X14
GPS_TAG_DESTLONGITUDEREF = 0X15
GPS_TAG_DESTLONGITUDE    = 0X16
GPS_TAG_DESTBEARINGREF   = 0X17
GPS_TAG_DESTBEARING      = 0X18
GPS_TAG_DESTDISTANCEREF  = 0X19
GPS_TAG_DESTDISTANCE     = 0X1A
GPS_TAG_PROCESSINGMETHOD = 0X1B
GPS_TAG_AREAINFORMATION  = 0X1C
GPS_TAG_DATESTAMP        = 0X1D
GPS_TAG_DIFFERENTIAL     = 0X1E

GpsTagTable = {}
GpsTagTable[GPS_TAG_VERSIONID]       = "VersionID"
GpsTagTable[GPS_TAG_LATITUDEREF]     = "LatitudeRef"
GpsTagTable[GPS_TAG_LATITUDE]        = "Latitude"
GpsTagTable[GPS_TAG_LONGITUDEREF]    = "LongitudeRef"
GpsTagTable[GPS_TAG_LONGITUDE]       = "Longitude"
GpsTagTable[GPS_TAG_ALTITUDEREF]     = "AltitudeRef"
GpsTagTable[GPS_TAG_ALTITUDE]        = "Altitude"
GpsTagTable[GPS_TAG_TIMESTAMP]       = "Timestamp"
GpsTagTable[GPS_TAG_SATELLITES]      = "Satellites"
GpsTagTable[GPS_TAG_STATUS]          = "Status"
GpsTagTable[GPS_TAG_MEASUREMODE]     = "MeasureMode"
GpsTagTable[GPS_TAG_DOP]             = "Dop"
GpsTagTable[GPS_TAG_SPEEDREF]        = "SpeedRef"
GpsTagTable[GPS_TAG_SPEED]           = "Speed"
GpsTagTable[GPS_TAG_TRACKREF]        = "TrafRef"
GpsTagTable[GPS_TAG_TRACK]           = "Track"
GpsTagTable[GPS_TAG_IMGDIRECTIONREF] = "ImgDirectionRef"
GpsTagTable[GPS_TAG_IMGDIRECTION]    = "ImgDirection"
GpsTagTable[GPS_TAG_MAPDATUM]        = "MapDatum"
GpsTagTable[GPS_TAG_DESTLATITUDEREF] = "DestLatitudeRef"
GpsTagTable[GPS_TAG_DESTLATITUDE]    = "DestLatitude"
GpsTagTable[GPS_TAG_DESTLONGITUDEREF]= "DestLongitudeRef"
GpsTagTable[GPS_TAG_DESTLONGITUDE]   = "DestLongitude"
GpsTagTable[GPS_TAG_DESTBEARINGREF]  = "DestBearingref"
GpsTagTable[GPS_TAG_DESTBEARING]     = "DestBearing"
GpsTagTable[GPS_TAG_DESTDISTANCEREF] = "DestDistanceRef"
GpsTagTable[GPS_TAG_DESTDISTANCE]    = "DestDistance"
GpsTagTable[GPS_TAG_PROCESSINGMETHOD]= "ProcessingMethod"
GpsTagTable[GPS_TAG_AREAINFORMATION] = "AreaInformation"
GpsTagTable[GPS_TAG_DATESTAMP]       = "Datestamp"
GpsTagTable[GPS_TAG_DIFFERENTIAL]    = "Differential"

FMT_BYTE      =  1
FMT_STRING    =  2
FMT_USHORT    =  3
FMT_ULONG     =  4
FMT_URATIONAL =  5
FMT_SBYTE     =  6
FMT_UNDEFINED =  7
FMT_SSHORT    =  8
FMT_SLONG     =  9
FMT_SRATIONAL = 10
FMT_SINGLE    = 11
FMT_DOUBLE    = 12

bytes_per_format = {0,1,1,2,4,8,1,1,2,4,8,4,8}

portrule = shortport.http

---Unpack a rational number from exif. In exif, a rational number is stored
--as a pair of integers - the numerator and the denominator.
--
--@return the new position, and the value.
local function unpack_rational(endian, data, pos)
  local v1, v2
  v1, v2, pos = string.unpack(endian .. "I4I4", data, pos)
  return pos, v1 / v2
end

local function process_gps(data, pos, endian, result)
  local value, num_entries
  local latitude, latitude_ref, longitude, longitude_ref

  -- The first entry in the gps section is a 16-bit size
  num_entries, pos = string.unpack(endian .. "I2", data, pos)

  -- Loop through the entries to find the fun stuff
  for i=1, num_entries do
    local tag, format, components, value
    tag, format, components, value, pos = string.unpack(endian .. "I2 I2 I4 I4", data, pos)

    if(tag == GPS_TAG_LATITUDE or tag == GPS_TAG_LONGITUDE) then
      local dummy, gps, h, m, s
      dummy, h = unpack_rational(endian, data, value + 8)
      dummy, m = unpack_rational(endian, data, dummy)
      dummy, s = unpack_rational(endian, data, dummy)

      gps = h + (m / 60) + (s / 60 / 60)

      if(tag == GPS_TAG_LATITUDE) then
        latitude = gps
      else
        longitude = gps
      end
    elseif(tag == GPS_TAG_LATITUDEREF) then
      -- Get the first byte in the latitude reference as a character
      latitude_ref = string.char(value >> 24)
    elseif(tag == GPS_TAG_LONGITUDEREF) then
      -- Get the first byte in the longitude reference as a character
      longitude_ref = string.char(value >> 24)
    end
  end

  if(latitude and longitude) then
    -- Normalize the N/S/E/W to positive and negative
    if(latitude_ref == 'S') then
      latitude = -latitude
    end
    if(longitude_ref == 'W') then
      longitude = -longitude
    end

    table.insert(result, string.format("GPS: %f,%f - https://maps.google.com/maps?q=%s,%s", latitude, longitude, latitude, longitude))
  end

  return true, result
end

---Parse the exif data section and return a table. This has only been tested
--in a .jpeg file, but should work for .tiff as well.
local function parse_exif(exif_data)
  local sig, marker, size
  local tag, format, components, byte_count, value, offset, dummy, data
  local status, result
  local tiff_header_1, first_offset

  -- Initialize the result table
  result = {}

  -- Read the verify the EXIF header
  local header, endian, pos = string.unpack(">c6 I2", exif_data, 1)
  if(header ~= "Exif\0\0") then
    return false, "Invalid EXIF header"
  end

  -- Check the endianness - it should only ever be big endian, but it doesn't
  -- hurt to check
  if(endian == 0x4d4d) then
    endian = ">"
  elseif(endian == 0x4949) then
    endian = "<"
  else
    return false, "Unrecognized endianness entry"
  end

  -- Read the first tiff header and the offset to the first data entry (should be 8)
  tiff_header_1, first_offset, pos = string.unpack(endian .. "I2 I4", exif_data, pos)
  if(tiff_header_1 ~= 0x002A or first_offset ~= 0x00000008) then
    return false, "Invalid tiff header"
  end

  -- Skip over the header, and go to the first offset (subtracting 1 because lua)
  pos = first_offset + 8 - 1

  -- The first 16-bit value is the number of entries
  local num_entries, pos = string.unpack(endian .. "I2", exif_data, pos)

  -- Loop through the entries
  for i=1,num_entries do
    -- Read the entry's header
    tag, format, components, value, pos = string.unpack(endian .. "I2 I2 I4 I4", exif_data, pos)

    -- Look at the tags we care about
    if(tag == TAG_GPSINFO) then
      -- If it's a GPSINFO tag, we need to parse the GPS structure
      status, result = process_gps(exif_data, value + 8 - 1, endian, result)
      if(not(status)) then
        return false, result
      end
    else
      value = string.unpack("z", exif_data, value + 8 - 1)
      if (tag == TAG_MAKE) then
        table.insert(result, string.format("Make: %s", value))
      elseif(tag == TAG_MODEL) then
        table.insert(result, string.format("Model: %s", value))
      elseif(tag == TAG_DATETIME) then
        table.insert(result, string.format("Date: %s", value))
      end
    end
  end

  return true, result
end

---Parse a jpeg and find the EXIF data section
local function parse_jpeg(s)
  local pos, sig, marker, size, exif_data

  -- Parse the jpeg header, make sure it's valid (we expect 0xFFD8)
  sig, pos = string.unpack(">I2", s, pos)
  if(sig ~= 0xFFD8) then
    return false, "Unexpected signature"
  end

  -- Parse the sections to find the exif marker (0xffe1)
  while(true) do
    marker, size, pos = string.unpack(">I2I2", s, pos)

    -- Check if we found the exif metadata section, break if we did
    if(marker == 0xffe1) then
      break
    -- If the marker is nil, we're off the end of the image (and therefore, it wasn't found)
    elseif(not(marker)) then
      return false, "Could not found EXIF marker"
    end

    -- Go to the next section (we subtract 2 because of the 2-byte marker we read)
    pos = pos + size - 2
  end

  exif_data, pos = string.unpack(string.format(">c%d", size), s, pos)

  return parse_exif(exif_data)
end


function action(host, port)
  local pattern = "%.jpg"
  local images = {}
  local results = {}

  -- once we know the pattern we'll be searching for, we can set up the function
  local whitelist = function(url)
    return string.match(url.file, "%.jpg") or string.match(url.file, "%.jpeg")
  end

  local crawler = httpspider.Crawler:new(  host, port, nil, { scriptname = SCRIPT_NAME, whitelist = { whitelist }} )

  if ( not(crawler) ) then
    return
  end

  while(true) do
    -- Begin the crawler
    local status, r = crawler:crawl()

    -- Make sure there's no error
    if ( not(status) ) then
      if ( r.err ) then
        return stdnse.format_output(false, r.reason)
      else
        break
      end
    end

    -- Check if we got a response, and the response is a .jpg file
    if r.response and r.response.body and r.response.status==200 and (string.match(r.url.path, ".jpg") or string.match(r.url.path, ".jpeg")) then
      local status, result
      stdnse.debug1("Attempting to read exif data from %s", r.url.raw)
      status, result = parse_jpeg(r.response.body)
      if(not(status)) then
        stdnse.debug1("Couldn't read exif from %s: %s", r.url.raw, result)
      else
        -- If there are any exif results, add them to the result
        if(result and #result > 0) then
          result['name'] = r.url.raw
          table.insert(results, result)
        end
      end
    end
  end

  return stdnse.format_output(true, results)
end

