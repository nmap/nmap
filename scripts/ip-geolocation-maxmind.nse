local bit = require "bit"
local geoip = require "geoip"
local io = require "io"
local ipOps = require "ipOps"
local math = require "math"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"

-- TODO: Support IPv6. Database format supports it, but we need to be able to
-- do equivalent of bit operations on 128-bit integers to make it work.

description = [[
Tries to identify the physical location of an IP address using a
Geolocation Maxmind database file (available from
http://www.maxmind.com/app/ip-location). This script supports queries
using all Maxmind databases that are supported by their API including
the commercial ones.
]]

---
-- @usage
-- nmap --script ip-geolocation-maxmind <target> [--script-args ip-geolocation.maxmind_db=<filename>]
--
-- @arg maxmind_db string indicates which file to use as a Maxmind database
--
-- @output
-- | ip-geolocation-maxmind:
-- | 74.207.244.221 (scanme.nmap.org)
-- |   coordinates (lat,lon): 39.4899,-74.4773
-- |_  city: Absecon, Philadelphia, PA, United States
---

author = "Gorjan Petrovski"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","external","safe"}

local function get_db_file()
  return (stdnse.get_script_args(SCRIPT_NAME .. ".maxmind_db") or
    nmap.fetchfile("nselib/data/GeoLiteCity.dat"))
end

hostrule = function(host)
  if nmap.address_family() ~= "inet" then
    stdnse.verbose1("Only IPv4 is currently supported.")
    return false
  end
  local is_private, err = ipOps.isPrivate( host.ip )
  if is_private then
    return false
  end
  if not get_db_file() then
    stdnse.verbose1("You must specify a Maxmind database file with the maxmind_db argument.")
    stdnse.verbose1("Download the database from http://dev.maxmind.com/geoip/legacy/geolite/")
    return false
  end
  return true
end

local MaxmindDef = {
  -- Database structure constants
  COUNTRY_BEGIN = 16776960,
  STATE_BEGIN_REV0 = 16700000,
  STATE_BEGIN_REV1 = 16000000,

  STRUCTURE_INFO_MAX_SIZE = 20,
  DATABASE_INFO_MAX_SIZE = 100,

  -- Database editions,
  COUNTRY_EDITION = 1,
  REGION_EDITION_REV0 = 7,
  REGION_EDITION_REV1 = 3,
  CITY_EDITION_REV0 = 6,
  CITY_EDITION_REV1 = 2,
  ORG_EDITION = 5,
  ISP_EDITION = 4,
  PROXY_EDITION = 8,
  ASNUM_EDITION = 9,
  NETSPEED_EDITION = 11,
  COUNTRY_EDITION_V6 = 12,

  SEGMENT_RECORD_LENGTH = 3,
  STANDARD_RECORD_LENGTH = 3,
  ORG_RECORD_LENGTH = 4,
  MAX_RECORD_LENGTH = 4,
  MAX_ORG_RECORD_LENGTH = 300,
  FULL_RECORD_LENGTH = 50,

  US_OFFSET = 1,
  CANADA_OFFSET = 677,
  WORLD_OFFSET = 1353,
  FIPS_RANGE = 360,
  DMA_MAP = {
    [500] = 'Portland-Auburn, ME',
    [501] = 'New York, NY',
    [502] = 'Binghamton, NY',
    [503] = 'Macon, GA',
    [504] = 'Philadelphia, PA',
    [505] = 'Detroit, MI',
    [506] = 'Boston, MA',
    [507] = 'Savannah, GA',
    [508] = 'Pittsburgh, PA',
    [509] = 'Ft Wayne, IN',
    [510] = 'Cleveland, OH',
    [511] = 'Washington, DC',
    [512] = 'Baltimore, MD',
    [513] = 'Flint, MI',
    [514] = 'Buffalo, NY',
    [515] = 'Cincinnati, OH',
    [516] = 'Erie, PA',
    [517] = 'Charlotte, NC',
    [518] = 'Greensboro, NC',
    [519] = 'Charleston, SC',
    [520] = 'Augusta, GA',
    [521] = 'Providence, RI',
    [522] = 'Columbus, GA',
    [523] = 'Burlington, VT',
    [524] = 'Atlanta, GA',
    [525] = 'Albany, GA',
    [526] = 'Utica-Rome, NY',
    [527] = 'Indianapolis, IN',
    [528] = 'Miami, FL',
    [529] = 'Louisville, KY',
    [530] = 'Tallahassee, FL',
    [531] = 'Tri-Cities, TN',
    [532] = 'Albany-Schenectady-Troy, NY',
    [533] = 'Hartford, CT',
    [534] = 'Orlando, FL',
    [535] = 'Columbus, OH',
    [536] = 'Youngstown-Warren, OH',
    [537] = 'Bangor, ME',
    [538] = 'Rochester, NY',
    [539] = 'Tampa, FL',
    [540] = 'Traverse City-Cadillac, MI',
    [541] = 'Lexington, KY',
    [542] = 'Dayton, OH',
    [543] = 'Springfield-Holyoke, MA',
    [544] = 'Norfolk-Portsmouth, VA',
    [545] = 'Greenville-New Bern-Washington, NC',
    [546] = 'Columbia, SC',
    [547] = 'Toledo, OH',
    [548] = 'West Palm Beach, FL',
    [549] = 'Watertown, NY',
    [550] = 'Wilmington, NC',
    [551] = 'Lansing, MI',
    [552] = 'Presque Isle, ME',
    [553] = 'Marquette, MI',
    [554] = 'Wheeling, WV',
    [555] = 'Syracuse, NY',
    [556] = 'Richmond-Petersburg, VA',
    [557] = 'Knoxville, TN',
    [558] = 'Lima, OH',
    [559] = 'Bluefield-Beckley-Oak Hill, WV',
    [560] = 'Raleigh-Durham, NC',
    [561] = 'Jacksonville, FL',
    [563] = 'Grand Rapids, MI',
    [564] = 'Charleston-Huntington, WV',
    [565] = 'Elmira, NY',
    [566] = 'Harrisburg-Lancaster-Lebanon-York, PA',
    [567] = 'Greenville-Spartenburg, SC',
    [569] = 'Harrisonburg, VA',
    [570] = 'Florence-Myrtle Beach, SC',
    [571] = 'Ft Myers, FL',
    [573] = 'Roanoke-Lynchburg, VA',
    [574] = 'Johnstown-Altoona, PA',
    [575] = 'Chattanooga, TN',
    [576] = 'Salisbury, MD',
    [577] = 'Wilkes Barre-Scranton, PA',
    [581] = 'Terre Haute, IN',
    [582] = 'Lafayette, IN',
    [583] = 'Alpena, MI',
    [584] = 'Charlottesville, VA',
    [588] = 'South Bend, IN',
    [592] = 'Gainesville, FL',
    [596] = 'Zanesville, OH',
    [597] = 'Parkersburg, WV',
    [598] = 'Clarksburg-Weston, WV',
    [600] = 'Corpus Christi, TX',
    [602] = 'Chicago, IL',
    [603] = 'Joplin-Pittsburg, MO',
    [604] = 'Columbia-Jefferson City, MO',
    [605] = 'Topeka, KS',
    [606] = 'Dothan, AL',
    [609] = 'St Louis, MO',
    [610] = 'Rockford, IL',
    [611] = 'Rochester-Mason City-Austin, MN',
    [612] = 'Shreveport, LA',
    [613] = 'Minneapolis-St Paul, MN',
    [616] = 'Kansas City, MO',
    [617] = 'Milwaukee, WI',
    [618] = 'Houston, TX',
    [619] = 'Springfield, MO',
    [620] = 'Tuscaloosa, AL',
    [622] = 'New Orleans, LA',
    [623] = 'Dallas-Fort Worth, TX',
    [624] = 'Sioux City, IA',
    [625] = 'Waco-Temple-Bryan, TX',
    [626] = 'Victoria, TX',
    [627] = 'Wichita Falls, TX',
    [628] = 'Monroe, LA',
    [630] = 'Birmingham, AL',
    [631] = 'Ottumwa-Kirksville, IA',
    [632] = 'Paducah, KY',
    [633] = 'Odessa-Midland, TX',
    [634] = 'Amarillo, TX',
    [635] = 'Austin, TX',
    [636] = 'Harlingen, TX',
    [637] = 'Cedar Rapids-Waterloo, IA',
    [638] = 'St Joseph, MO',
    [639] = 'Jackson, TN',
    [640] = 'Memphis, TN',
    [641] = 'San Antonio, TX',
    [642] = 'Lafayette, LA',
    [643] = 'Lake Charles, LA',
    [644] = 'Alexandria, LA',
    [646] = 'Anniston, AL',
    [647] = 'Greenwood-Greenville, MS',
    [648] = 'Champaign-Springfield-Decatur, IL',
    [649] = 'Evansville, IN',
    [650] = 'Oklahoma City, OK',
    [651] = 'Lubbock, TX',
    [652] = 'Omaha, NE',
    [656] = 'Panama City, FL',
    [657] = 'Sherman, TX',
    [658] = 'Green Bay-Appleton, WI',
    [659] = 'Nashville, TN',
    [661] = 'San Angelo, TX',
    [662] = 'Abilene-Sweetwater, TX',
    [669] = 'Madison, WI',
    [670] = 'Ft Smith-Fay-Springfield, AR',
    [671] = 'Tulsa, OK',
    [673] = 'Columbus-Tupelo-West Point, MS',
    [675] = 'Peoria-Bloomington, IL',
    [676] = 'Duluth, MN',
    [678] = 'Wichita, KS',
    [679] = 'Des Moines, IA',
    [682] = 'Davenport-Rock Island-Moline, IL',
    [686] = 'Mobile, AL',
    [687] = 'Minot-Bismarck-Dickinson, ND',
    [691] = 'Huntsville, AL',
    [692] = 'Beaumont-Port Author, TX',
    [693] = 'Little Rock-Pine Bluff, AR',
    [698] = 'Montgomery, AL',
    [702] = 'La Crosse-Eau Claire, WI',
    [705] = 'Wausau-Rhinelander, WI',
    [709] = 'Tyler-Longview, TX',
    [710] = 'Hattiesburg-Laurel, MS',
    [711] = 'Meridian, MS',
    [716] = 'Baton Rouge, LA',
    [717] = 'Quincy, IL',
    [718] = 'Jackson, MS',
    [722] = 'Lincoln-Hastings, NE',
    [724] = 'Fargo-Valley City, ND',
    [725] = 'Sioux Falls, SD',
    [734] = 'Jonesboro, AR',
    [736] = 'Bowling Green, KY',
    [737] = 'Mankato, MN',
    [740] = 'North Platte, NE',
    [743] = 'Anchorage, AK',
    [744] = 'Honolulu, HI',
    [745] = 'Fairbanks, AK',
    [746] = 'Biloxi-Gulfport, MS',
    [747] = 'Juneau, AK',
    [749] = 'Laredo, TX',
    [751] = 'Denver, CO',
    [752] = 'Colorado Springs, CO',
    [753] = 'Phoenix, AZ',
    [754] = 'Butte-Bozeman, MT',
    [755] = 'Great Falls, MT',
    [756] = 'Billings, MT',
    [757] = 'Boise, ID',
    [758] = 'Idaho Falls-Pocatello, ID',
    [759] = 'Cheyenne, WY',
    [760] = 'Twin Falls, ID',
    [762] = 'Missoula, MT',
    [764] = 'Rapid City, SD',
    [765] = 'El Paso, TX',
    [766] = 'Helena, MT',
    [767] = 'Casper-Riverton, WY',
    [770] = 'Salt Lake City, UT',
    [771] = 'Yuma, AZ',
    [773] = 'Grand Junction, CO',
    [789] = 'Tucson, AZ',
    [790] = 'Albuquerque, NM',
    [798] = 'Glendive, MT',
    [800] = 'Bakersfield, CA',
    [801] = 'Eugene, OR',
    [802] = 'Eureka, CA',
    [803] = 'Los Angeles, CA',
    [804] = 'Palm Springs, CA',
    [807] = 'San Francisco, CA',
    [810] = 'Yakima-Pasco, WA',
    [811] = 'Reno, NV',
    [813] = 'Medford-Klamath Falls, OR',
    [819] = 'Seattle-Tacoma, WA',
    [820] = 'Portland, OR',
    [821] = 'Bend, OR',
    [825] = 'San Diego, CA',
    [828] = 'Monterey-Salinas, CA',
    [839] = 'Las Vegas, NV',
    [855] = 'Santa Barbara, CA',
    [862] = 'Sacramento, CA',
    [866] = 'Fresno, CA',
    [868] = 'Chico-Redding, CA',
    [881] = 'Spokane, WA'
  },
  COUNTRY_CODES = {
    '', 'AP', 'EU', 'AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AN', 'AO', 'AQ',
    'AR', 'AS', 'AT', 'AU', 'AW', 'AZ', 'BA', 'BB', 'BD', 'BE', 'BF', 'BG', 'BH',
    'BI', 'BJ', 'BM', 'BN', 'BO', 'BR', 'BS', 'BT', 'BV', 'BW', 'BY', 'BZ', 'CA',
    'CC', 'CD', 'CF', 'CG', 'CH', 'CI', 'CK', 'CL', 'CM', 'CN', 'CO', 'CR', 'CU',
    'CV', 'CX', 'CY', 'CZ', 'DE', 'DJ', 'DK', 'DM', 'DO', 'DZ', 'EC', 'EE', 'EG',
    'EH', 'ER', 'ES', 'ET', 'FI', 'FJ', 'FK', 'FM', 'FO', 'FR', 'FX', 'GA', 'GB',
    'GD', 'GE', 'GF', 'GH', 'GI', 'GL', 'GM', 'GN', 'GP', 'GQ', 'GR', 'GS', 'GT',
    'GU', 'GW', 'GY', 'HK', 'HM', 'HN', 'HR', 'HT', 'HU', 'ID', 'IE', 'IL', 'IN',
    'IO', 'IQ', 'IR', 'IS', 'IT', 'JM', 'JO', 'JP', 'KE', 'KG', 'KH', 'KI', 'KM',
    'KN', 'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB', 'LC', 'LI', 'LK', 'LR', 'LS',
    'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'MG', 'MH', 'MK', 'ML', 'MM', 'MN',
    'MO', 'MP', 'MQ', 'MR', 'MS', 'MT', 'MU', 'MV', 'MW', 'MX', 'MY', 'MZ', 'NA',
    'NC', 'NE', 'NF', 'NG', 'NI', 'NL', 'NO', 'NP', 'NR', 'NU', 'NZ', 'OM', 'PA',
    'PE', 'PF', 'PG', 'PH', 'PK', 'PL', 'PM', 'PN', 'PR', 'PS', 'PT', 'PW', 'PY',
    'QA', 'RE', 'RO', 'RU', 'RW', 'SA', 'SB', 'SC', 'SD', 'SE', 'SG', 'SH', 'SI',
    'SJ', 'SK', 'SL', 'SM', 'SN', 'SO', 'SR', 'ST', 'SV', 'SY', 'SZ', 'TC', 'TD',
    'TF', 'TG', 'TH', 'TJ', 'TK', 'TM', 'TN', 'TO', 'TL', 'TR', 'TT', 'TV', 'TW',
    'TZ', 'UA', 'UG', 'UM', 'US', 'UY', 'UZ', 'VA', 'VC', 'VE', 'VG', 'VI', 'VN',
    'VU', 'WF', 'WS', 'YE', 'YT', 'RS', 'ZA', 'ZM', 'ME', 'ZW', 'A1', 'A2', 'O1',
    'AX', 'GG', 'IM', 'JE', 'BL', 'MF'
  },
  COUNTRY_CODES3 = {
    '','AP','EU','AND','ARE','AFG','ATG','AIA','ALB','ARM','ANT','AGO','AQ','ARG',
    'ASM','AUT','AUS','ABW','AZE','BIH','BRB','BGD','BEL','BFA','BGR','BHR','BDI',
    'BEN','BMU','BRN','BOL','BRA','BHS','BTN','BV','BWA','BLR','BLZ','CAN','CC',
    'COD','CAF','COG','CHE','CIV','COK','CHL','CMR','CHN','COL','CRI','CUB','CPV',
    'CX','CYP','CZE','DEU','DJI','DNK','DMA','DOM','DZA','ECU','EST','EGY','ESH',
    'ERI','ESP','ETH','FIN','FJI','FLK','FSM','FRO','FRA','FX','GAB','GBR','GRD',
    'GEO','GUF','GHA','GIB','GRL','GMB','GIN','GLP','GNQ','GRC','GS','GTM','GUM',
    'GNB','GUY','HKG','HM','HND','HRV','HTI','HUN','IDN','IRL','ISR','IND','IO',
    'IRQ','IRN','ISL','ITA','JAM','JOR','JPN','KEN','KGZ','KHM','KIR','COM','KNA',
    'PRK','KOR','KWT','CYM','KAZ','LAO','LBN','LCA','LIE','LKA','LBR','LSO','LTU',
    'LUX','LVA','LBY','MAR','MCO','MDA','MDG','MHL','MKD','MLI','MMR','MNG','MAC',
    'MNP','MTQ','MRT','MSR','MLT','MUS','MDV','MWI','MEX','MYS','MOZ','NAM','NCL',
    'NER','NFK','NGA','NIC','NLD','NOR','NPL','NRU','NIU','NZL','OMN','PAN','PER',
    'PYF','PNG','PHL','PAK','POL','SPM','PCN','PRI','PSE','PRT','PLW','PRY','QAT',
    'REU','ROU','RUS','RWA','SAU','SLB','SYC','SDN','SWE','SGP','SHN','SVN','SJM',
    'SVK','SLE','SMR','SEN','SOM','SUR','STP','SLV','SYR','SWZ','TCA','TCD','TF',
    'TGO','THA','TJK','TKL','TLS','TKM','TUN','TON','TUR','TTO','TUV','TWN','TZA',
    'UKR','UGA','UM','USA','URY','UZB','VAT','VCT','VEN','VGB','VIR','VNM','VUT',
    'WLF','WSM','YEM','YT','SRB','ZAF','ZMB','MNE','ZWE','A1','A2','O1',
    'ALA','GGY','IMN','JEY','BLM','MAF'
  },
  COUNTRY_NAMES = {
    "", "Asia/Pacific Region", "Europe", "Andorra", "United Arab Emirates",
    "Afghanistan", "Antigua and Barbuda", "Anguilla", "Albania", "Armenia",
    "Netherlands Antilles", "Angola", "Antarctica", "Argentina", "American Samoa",
    "Austria", "Australia", "Aruba", "Azerbaijan", "Bosnia and Herzegovina",
    "Barbados", "Bangladesh", "Belgium", "Burkina Faso", "Bulgaria", "Bahrain",
    "Burundi", "Benin", "Bermuda", "Brunei Darussalam", "Bolivia", "Brazil",
    "Bahamas", "Bhutan", "Bouvet Island", "Botswana", "Belarus", "Belize",
    "Canada", "Cocos (Keeling) Islands", "Congo, The Democratic Republic of the",
    "Central African Republic", "Congo", "Switzerland", "Cote D'Ivoire", "Cook Islands",
    "Chile", "Cameroon", "China", "Colombia", "Costa Rica", "Cuba", "Cape Verde",
    "Christmas Island", "Cyprus", "Czech Republic", "Germany", "Djibouti",
    "Denmark", "Dominica", "Dominican Republic", "Algeria", "Ecuador", "Estonia",
    "Egypt", "Western Sahara", "Eritrea", "Spain", "Ethiopia", "Finland", "Fiji",
    "Falkland Islands (Malvinas)", "Micronesia, Federated States of", "Faroe Islands",
    "France", "France, Metropolitan", "Gabon", "United Kingdom",
    "Grenada", "Georgia", "French Guiana", "Ghana", "Gibraltar", "Greenland",
    "Gambia", "Guinea", "Guadeloupe", "Equatorial Guinea", "Greece",
    "South Georgia and the South Sandwich Islands",
    "Guatemala", "Guam", "Guinea-Bissau",
    "Guyana", "Hong Kong", "Heard Island and McDonald Islands", "Honduras",
    "Croatia", "Haiti", "Hungary", "Indonesia", "Ireland", "Israel", "India",
    "British Indian Ocean Territory", "Iraq", "Iran, Islamic Republic of",
    "Iceland", "Italy", "Jamaica", "Jordan", "Japan", "Kenya", "Kyrgyzstan",
    "Cambodia", "Kiribati", "Comoros", "Saint Kitts and Nevis",
    "Korea, Democratic People's Republic of",
    "Korea, Republic of", "Kuwait", "Cayman Islands",
    "Kazakstan", "Lao People's Democratic Republic", "Lebanon", "Saint Lucia",
    "Liechtenstein", "Sri Lanka", "Liberia", "Lesotho", "Lithuania", "Luxembourg",
    "Latvia", "Libyan Arab Jamahiriya", "Morocco", "Monaco", "Moldova, Republic of",
    "Madagascar", "Marshall Islands", "Macedonia",
    "Mali", "Myanmar", "Mongolia", "Macau", "Northern Mariana Islands",
    "Martinique", "Mauritania", "Montserrat", "Malta", "Mauritius", "Maldives",
    "Malawi", "Mexico", "Malaysia", "Mozambique", "Namibia", "New Caledonia",
    "Niger", "Norfolk Island", "Nigeria", "Nicaragua", "Netherlands", "Norway",
    "Nepal", "Nauru", "Niue", "New Zealand", "Oman", "Panama", "Peru", "French Polynesia",
    "Papua New Guinea", "Philippines", "Pakistan", "Poland", "Saint Pierre and Miquelon",
    "Pitcairn Islands", "Puerto Rico", "Palestinian Territory",
    "Portugal", "Palau", "Paraguay", "Qatar", "Reunion", "Romania",
    "Russian Federation", "Rwanda", "Saudi Arabia", "Solomon Islands",
    "Seychelles", "Sudan", "Sweden", "Singapore", "Saint Helena", "Slovenia",
    "Svalbard and Jan Mayen", "Slovakia", "Sierra Leone", "San Marino", "Senegal",
    "Somalia", "Suriname", "Sao Tome and Principe", "El Salvador", "Syrian Arab Republic",
    "Swaziland", "Turks and Caicos Islands", "Chad", "French Southern Territories",
    "Togo", "Thailand", "Tajikistan", "Tokelau", "Turkmenistan",
    "Tunisia", "Tonga", "Timor-Leste", "Turkey", "Trinidad and Tobago", "Tuvalu",
    "Taiwan", "Tanzania, United Republic of", "Ukraine",
    "Uganda", "United States Minor Outlying Islands", "United States", "Uruguay",
    "Uzbekistan", "Holy See (Vatican City State)", "Saint Vincent and the Grenadines",
    "Venezuela", "Virgin Islands, British", "Virgin Islands, U.S.",
    "Vietnam", "Vanuatu", "Wallis and Futuna", "Samoa", "Yemen", "Mayotte",
    "Serbia", "South Africa", "Zambia", "Montenegro", "Zimbabwe",
    "Anonymous Proxy","Satellite Provider","Other",
    "Aland Islands","Guernsey","Isle of Man","Jersey","Saint Barthelemy","Saint Martin"
  }
}

local record_metatable = {
  __tostring = function(loc)
    local output = {
    "coordinates (lat,lon): ", loc.latitude, ",", loc.longitude, "\n"
    }

    if loc.city then
      output[#output+1] = "city: "..loc.city
    end
    if loc.metro_code then
      output[#output+1] = ", "..loc.metro_code
    end
    if loc.country_name then
      output[#output+1] = ", "..loc.country_name
    end
    output[#output+1] = "\n"
    return table.concat(output)
  end
}
local GeoIP = {
  new = function(self, filename)
    if not(filename) then
      return nil
    end

    local o = {}
    setmetatable(o, self)
    self.__index = self
    o._filename=filename
    local err
    o._filehandle= assert(io.open(filename,'rb'))
    o._databaseType = MaxmindDef.COUNTRY_EDITION
    o._recordLength = MaxmindDef.STANDARD_RECORD_LENGTH

    local filepos = o._filehandle:seek()
    o._filehandle:seek("end",-3)

    for i=1,MaxmindDef.STRUCTURE_INFO_MAX_SIZE do
      local delim = o._filehandle:read(3)

      if delim == '\255\255\255' then
        o._databaseType = o._filehandle:read(1):byte()
        -- backward compatibility with databases from April 2003 and earlier
        if (o._databaseType >= 106) then
          o._databaseType = o._databaseType - 105
        end

        local fast_combo1={[MaxmindDef.CITY_EDITION_REV0]=true,
        [MaxmindDef.CITY_EDITION_REV1]=true,
        [MaxmindDef.ORG_EDITION]=true,
        [MaxmindDef.ISP_EDITION]=true,
        [MaxmindDef.ASNUM_EDITION]=true}

        if o._databaseType == MaxmindDef.REGION_EDITION_REV0 then
          o._databaseSegments = MaxmindDef.STATE_BEGIN_REV0
        elseif o._databaseType == MaxmindDef.REGION_EDITION_REV1 then
          o._databaseSegments = MaxmindDef.STATE_BEGIN_REV1
        elseif fast_combo1[o._databaseType] then
          o._databaseSegments = 0
          local buf = o._filehandle:read(MaxmindDef.SEGMENT_RECORD_LENGTH)

          -- the original representation in the MaxMind API is ANSI C integer
          -- which should not overflow the greatest value Lua can offer ;)
          for j=0,(MaxmindDef.SEGMENT_RECORD_LENGTH-1) do
            o._databaseSegments = o._databaseSegments + bit.lshift( buf:byte(j+1), j*8)
          end

          if o._databaseType == MaxmindDef.ORG_EDITION or o._databaseType == MaxmindDef.ISP_EDITION then
            o._recordLength = MaxmindDef.ORG_RECORD_LENGTH
          end
        end
        break
      else
        o._filehandle:seek("cur",-4)
      end
    end

    if o._databaseType == MaxmindDef.COUNTRY_EDITION then
      o._databaseSegments = MaxmindDef.COUNTRY_BEGIN
    end
    o._filehandle:seek("set",filepos)

    return o
  end,

  output_record_by_addr = function(self,addr)
    local loc = self:record_by_addr(addr)
    if not loc then return nil end
    geoip.add(addr, loc.latitude, loc.longitude)
    setmetatable(loc, record_metatable)
    return loc
  end,

  record_by_addr=function(self,addr)
    local ipnum = ipOps.todword(addr)
    return self:_get_record(ipnum)
  end,

  _get_record=function(self,ipnum)
    local seek_country = self:_seek_country(ipnum)
    if seek_country == self._databaseSegments then
      return nil
    end
    local record_pointer = seek_country + (2 * self._recordLength - 1) * self._databaseSegments

    self._filehandle:seek("set",record_pointer)
    local record_buf = self._filehandle:read(MaxmindDef.FULL_RECORD_LENGTH)

    local record = {}
    local start_pos = 1
    local char = record_buf:byte(start_pos)
    char=char+1
    record.country_code = MaxmindDef.COUNTRY_CODES[char]
    record.country_code3 = MaxmindDef.COUNTRY_CODES3[char]
    record.country_name = MaxmindDef.COUNTRY_NAMES[char]
    start_pos = start_pos + 1
    local end_pos = 0

    end_pos = record_buf:find("\0",start_pos)
    if start_pos ~= end_pos then
      record.region_name = record_buf:sub(start_pos, end_pos-1)
    end
    start_pos = end_pos + 1

    end_pos = record_buf:find("\0",start_pos)
    if start_pos ~= end_pos then
      record.city = record_buf:sub(start_pos, end_pos-1)
    end
    start_pos = end_pos + 1


    end_pos = record_buf:find("\0",start_pos)
    if start_pos ~= end_pos then
      record.postal_code = record_buf:sub(start_pos, end_pos-1)
    end
    start_pos = end_pos + 1

    local c1,c2,c3=record_buf:byte(start_pos,start_pos+3)
    record.latitude = (( bit.lshift(c1,0*8) + bit.lshift(c2,1*8) + bit.lshift(c3,2*8) )/10000) - 180
    start_pos = start_pos +3

    c1,c2,c3=record_buf:byte(start_pos,start_pos+3)
    record.longitude = (( bit.lshift(c1,0*8) + bit.lshift(c2,1*8) + bit.lshift(c3,2*8) )/10000) - 180
    start_pos = start_pos +3

    if self._databaseType == MaxmindDef.CITY_EDITION_REV1 and record.country_code=='US' then
      c1,c2,c3=record_buf:byte(start_pos,start_pos+3)
      local dmaarea_combo= bit.lshift(c1,0*8) + bit.lshift(c2,1*8) + bit.lshift(c3,2*8)
      record.dma_code = math.floor(dmaarea_combo/1000)
      record.area_code = dmaarea_combo % 1000
    else
      record.dma_code = nil
      record.area_code = nil
    end

    if record.dma_code and MaxmindDef.DMA_MAP[record.dma_code] then
      record.metro_code = MaxmindDef.DMA_MAP[record.dma_code]
    else
      record.metro_code = nil
    end

    return record
  end,

  _seek_country=function(self,ipnum)
    local offset = 0
    for depth=31,0,-1 do
      self._filehandle:seek("set", 2 * self._recordLength * offset)
      local buf = self._filehandle:read(2*self._recordLength)

      local x = {}
      x[0],x[1] = 0,0

      for i=0,1 do
        for j=0,(self._recordLength-1) do
          x[i] = x[i] + bit.lshift(buf:byte((self._recordLength * i + j) +1 ), j*8)
        end
      end
      -- Gotta test this out thoroughly because of the ipnum
      if bit.band(ipnum, bit.lshift(1,depth)) ~= 0 then
        if x[1] >= self._databaseSegments then
          return x[1]
        end
        offset = x[1]
      else
        if x[0] >= self._databaseSegments then
          return x[0]
        end
        offset = x[0]
      end
    end
    stdnse.debug1('Error traversing database - perhaps it is corrupt?')
    return nil
  end,
}

action = function(host,port)
  local gi = nmap.registry.maxmind_db
  if not gi then
    local f_maxmind = get_db_file()
    gi = assert( GeoIP:new(f_maxmind), "Wrong file specified for a Maxmind database")
    nmap.registry.maxmind_db = gi
  end

  return gi:output_record_by_addr(host.ip)
end
