package upstreamproxy

import "strings"

// The built-in country table: mobile country codes as assigned by
// ITU-T E.212, with the ISO 3166-1 alpha-2 code of each country or territory.
//
// It is the offline fallback for the downloaded MCC/MNC table. That table is
// preferred whenever it is available because it also knows which network
// (MCC+MNC) belongs to which territory; this one only knows the MCC. Where
// several territories share an MCC, the one holding the bulk of the networks
// comes first and the others follow.
//
// MCCs are reassigned very rarely, so this list ages slowly; a successful
// download replaces it anyway.
var builtinMCCCountries = []struct {
	mcc   string
	codes string // comma separated, main country first
}{
	// Europe
	{"202", "GR"}, {"204", "NL"}, {"206", "BE"}, {"208", "FR"}, {"212", "MC"},
	{"213", "AD"}, {"214", "ES"}, {"216", "HU"}, {"218", "BA"}, {"219", "HR"},
	{"220", "RS"}, {"221", "XK"}, {"222", "IT"}, {"225", "VA"}, {"226", "RO"},
	{"228", "CH"}, {"230", "CZ"}, {"231", "SK"}, {"232", "AT"},
	{"234", "GB,GG,IM,JE"}, {"235", "GB"},
	{"238", "DK"}, {"240", "SE"}, {"242", "NO"}, {"244", "FI"}, {"246", "LT"},
	{"247", "LV"}, {"248", "EE"}, {"250", "RU"}, {"255", "UA"}, {"257", "BY"},
	{"259", "MD"}, {"260", "PL"}, {"262", "DE"}, {"266", "GI"}, {"268", "PT"},
	{"270", "LU"}, {"272", "IE"}, {"274", "IS"}, {"276", "AL"}, {"278", "MT"},
	{"280", "CY"}, {"282", "GE"}, {"283", "AM"}, {"284", "BG"}, {"286", "TR"},
	{"288", "FO"}, {"290", "GL"}, {"292", "SM"}, {"293", "SI"}, {"294", "MK"},
	{"295", "LI"}, {"297", "ME"},

	// North America and the Caribbean
	{"302", "CA"}, {"308", "PM"},
	{"310", "US,GU,MP"}, {"311", "US,GU"}, {"312", "US"}, {"313", "US"},
	{"314", "US"}, {"315", "US"}, {"316", "US"},
	{"330", "PR"}, {"332", "VI"}, {"334", "MX"}, {"338", "JM"},
	{"340", "GP,MQ,GF,BL,MF"},
	{"342", "BB"}, {"344", "AG"}, {"346", "KY"}, {"348", "VG"}, {"350", "BM"},
	{"352", "GD"}, {"354", "MS"}, {"356", "KN"}, {"358", "LC"}, {"360", "VC"},
	{"362", "CW,SX,BQ"}, {"363", "AW"}, {"364", "BS"}, {"365", "AI"}, {"366", "DM"},
	{"368", "CU"}, {"370", "DO"}, {"372", "HT"}, {"374", "TT"}, {"376", "TC"},

	// Asia and the Middle East
	{"400", "AZ"}, {"401", "KZ"}, {"402", "BT"}, {"404", "IN"}, {"405", "IN"},
	{"406", "IN"}, {"410", "PK"}, {"412", "AF"}, {"413", "LK"}, {"414", "MM"},
	{"415", "LB"}, {"416", "JO"}, {"417", "SY"}, {"418", "IQ"}, {"419", "KW"},
	{"420", "SA"}, {"421", "YE"}, {"422", "OM"}, {"424", "AE"}, {"425", "IL,PS"},
	{"426", "BH"}, {"427", "QA"}, {"428", "MN"}, {"429", "NP"}, {"430", "AE"},
	{"431", "AE"}, {"432", "IR"}, {"434", "UZ"}, {"436", "TJ"}, {"437", "KG"},
	{"438", "TM"}, {"440", "JP"}, {"441", "JP"}, {"450", "KR"}, {"452", "VN"},
	{"454", "HK"}, {"455", "MO"}, {"456", "KH"}, {"457", "LA"}, {"460", "CN"},
	{"461", "CN"}, {"466", "TW"}, {"467", "KP"}, {"470", "BD"}, {"472", "MV"},

	// South-East Asia and Oceania
	{"502", "MY"}, {"505", "AU,NF"}, {"510", "ID"}, {"514", "TL"}, {"515", "PH"},
	{"520", "TH"}, {"525", "SG"}, {"528", "BN"}, {"530", "NZ"}, {"536", "NR"},
	{"537", "PG"}, {"539", "TO"}, {"540", "SB"}, {"541", "VU"}, {"542", "FJ"},
	{"543", "WF"}, {"544", "AS"}, {"545", "KI"}, {"546", "NC"}, {"547", "PF"},
	{"548", "CK"}, {"549", "WS"}, {"550", "FM"}, {"551", "MH"}, {"552", "PW"},
	{"553", "TV"}, {"554", "TK"}, {"555", "NU"},

	// Africa
	{"602", "EG"}, {"603", "DZ"}, {"604", "MA"}, {"605", "TN"}, {"606", "LY"},
	{"607", "GM"}, {"608", "SN"}, {"609", "MR"}, {"610", "ML"}, {"611", "GN"},
	{"612", "CI"}, {"613", "BF"}, {"614", "NE"}, {"615", "TG"}, {"616", "BJ"},
	{"617", "MU"}, {"618", "LR"}, {"619", "SL"}, {"620", "GH"}, {"621", "NG"},
	{"622", "TD"}, {"623", "CF"}, {"624", "CM"}, {"625", "CV"}, {"626", "ST"},
	{"627", "GQ"}, {"628", "GA"}, {"629", "CG"}, {"630", "CD"}, {"631", "AO"},
	{"632", "GW"}, {"633", "SC"}, {"634", "SD"}, {"635", "RW"}, {"636", "ET"},
	{"637", "SO"}, {"638", "DJ"}, {"639", "KE"}, {"640", "TZ"}, {"641", "UG"},
	{"642", "BI"}, {"643", "MZ"}, {"645", "ZM"}, {"646", "MG"}, {"647", "RE,YT"},
	{"648", "ZW"}, {"649", "NA"}, {"650", "MW"}, {"651", "LS"}, {"652", "BW"},
	{"653", "SZ"}, {"654", "KM"}, {"655", "ZA"}, {"657", "ER"}, {"658", "SH"},
	{"659", "SS"},

	// Central and South America
	{"702", "BZ"}, {"704", "GT"}, {"706", "SV"}, {"708", "HN"}, {"710", "NI"},
	{"712", "CR"}, {"714", "PA"}, {"716", "PE"}, {"722", "AR"}, {"724", "BR"},
	{"730", "CL"}, {"732", "CO"}, {"734", "VE"}, {"736", "BO"}, {"738", "GY"},
	{"740", "EC"}, {"742", "GF"}, {"744", "PY"}, {"746", "SR"}, {"748", "UY"},
	{"750", "FK"},
}

var builtinCountryNames = map[string]string{
	"AD": "Andorra", "AE": "United Arab Emirates", "AF": "Afghanistan", "AG": "Antigua and Barbuda",
	"AI": "Anguilla", "AL": "Albania", "AM": "Armenia", "AO": "Angola", "AR": "Argentina",
	"AS": "American Samoa", "AT": "Austria", "AU": "Australia", "AW": "Aruba", "AZ": "Azerbaijan",
	"BA": "Bosnia and Herzegovina", "BB": "Barbados", "BD": "Bangladesh", "BE": "Belgium",
	"BF": "Burkina Faso", "BG": "Bulgaria", "BH": "Bahrain", "BI": "Burundi", "BJ": "Benin",
	"BL": "Saint Barthelemy", "BM": "Bermuda", "BN": "Brunei", "BO": "Bolivia",
	"BQ": "Bonaire, Sint Eustatius and Saba", "BR": "Brazil", "BS": "Bahamas", "BT": "Bhutan",
	"BW": "Botswana", "BY": "Belarus", "BZ": "Belize", "CA": "Canada",
	"CD": "Democratic Republic of the Congo", "CF": "Central African Republic",
	"CG": "Republic of the Congo", "CH": "Switzerland", "CI": "Ivory Coast", "CK": "Cook Islands",
	"CL": "Chile", "CM": "Cameroon", "CN": "China", "CO": "Colombia", "CR": "Costa Rica",
	"CU": "Cuba", "CV": "Cape Verde", "CW": "Curacao", "CY": "Cyprus", "CZ": "Czech Republic",
	"DE": "Germany", "DJ": "Djibouti", "DK": "Denmark", "DM": "Dominica", "DO": "Dominican Republic",
	"DZ": "Algeria", "EC": "Ecuador", "EE": "Estonia", "EG": "Egypt", "ER": "Eritrea", "ES": "Spain",
	"ET": "Ethiopia", "FI": "Finland", "FJ": "Fiji", "FK": "Falkland Islands", "FM": "Micronesia",
	"FO": "Faroe Islands", "FR": "France", "GA": "Gabon", "GB": "United Kingdom", "GD": "Grenada",
	"GE": "Georgia", "GF": "French Guiana", "GG": "Guernsey", "GH": "Ghana", "GI": "Gibraltar",
	"GL": "Greenland", "GM": "Gambia", "GN": "Guinea", "GP": "Guadeloupe", "GQ": "Equatorial Guinea",
	"GR": "Greece", "GT": "Guatemala", "GU": "Guam", "GW": "Guinea-Bissau", "GY": "Guyana",
	"HK": "Hong Kong", "HN": "Honduras", "HR": "Croatia", "HT": "Haiti", "HU": "Hungary",
	"ID": "Indonesia", "IE": "Ireland", "IL": "Israel", "IM": "Isle of Man", "IN": "India",
	"IQ": "Iraq", "IR": "Iran", "IS": "Iceland", "IT": "Italy", "JE": "Jersey", "JM": "Jamaica",
	"JO": "Jordan", "JP": "Japan", "KE": "Kenya", "KG": "Kyrgyzstan", "KH": "Cambodia",
	"KI": "Kiribati", "KM": "Comoros", "KN": "Saint Kitts and Nevis", "KP": "North Korea",
	"KR": "South Korea", "KW": "Kuwait", "KY": "Cayman Islands", "KZ": "Kazakhstan", "LA": "Laos",
	"LB": "Lebanon", "LC": "Saint Lucia", "LI": "Liechtenstein", "LK": "Sri Lanka", "LR": "Liberia",
	"LS": "Lesotho", "LT": "Lithuania", "LU": "Luxembourg", "LV": "Latvia", "LY": "Libya",
	"MA": "Morocco", "MC": "Monaco", "MD": "Moldova", "ME": "Montenegro", "MF": "Saint Martin",
	"MG": "Madagascar", "MH": "Marshall Islands", "MK": "North Macedonia", "ML": "Mali",
	"MM": "Myanmar", "MN": "Mongolia", "MO": "Macau", "MP": "Northern Mariana Islands",
	"MQ": "Martinique", "MR": "Mauritania", "MS": "Montserrat", "MT": "Malta", "MU": "Mauritius",
	"MV": "Maldives", "MW": "Malawi", "MX": "Mexico", "MY": "Malaysia", "MZ": "Mozambique",
	"NA": "Namibia", "NC": "New Caledonia", "NE": "Niger", "NF": "Norfolk Island", "NG": "Nigeria",
	"NI": "Nicaragua", "NL": "Netherlands", "NO": "Norway", "NP": "Nepal", "NR": "Nauru",
	"NU": "Niue", "NZ": "New Zealand", "OM": "Oman", "PA": "Panama", "PE": "Peru",
	"PF": "French Polynesia", "PG": "Papua New Guinea", "PH": "Philippines", "PK": "Pakistan",
	"PL": "Poland", "PM": "Saint Pierre and Miquelon", "PR": "Puerto Rico", "PS": "Palestine",
	"PT": "Portugal", "PW": "Palau", "PY": "Paraguay", "QA": "Qatar", "RE": "Reunion",
	"RO": "Romania", "RS": "Serbia", "RU": "Russia", "RW": "Rwanda", "SA": "Saudi Arabia",
	"SB": "Solomon Islands", "SC": "Seychelles", "SD": "Sudan", "SE": "Sweden", "SG": "Singapore",
	"SH": "Saint Helena", "SI": "Slovenia", "SK": "Slovakia", "SL": "Sierra Leone",
	"SM": "San Marino", "SN": "Senegal", "SO": "Somalia", "SR": "Suriname", "SS": "South Sudan",
	"ST": "Sao Tome and Principe", "SV": "El Salvador", "SX": "Sint Maarten", "SY": "Syria",
	"SZ": "Eswatini", "TC": "Turks and Caicos Islands", "TD": "Chad", "TG": "Togo", "TH": "Thailand",
	"TJ": "Tajikistan", "TK": "Tokelau", "TL": "Timor-Leste", "TM": "Turkmenistan", "TN": "Tunisia",
	"TO": "Tonga", "TR": "Turkey", "TT": "Trinidad and Tobago", "TV": "Tuvalu", "TW": "Taiwan",
	"TZ": "Tanzania", "UA": "Ukraine", "UG": "Uganda", "US": "United States", "UY": "Uruguay",
	"UZ": "Uzbekistan", "VA": "Vatican City", "VC": "Saint Vincent and the Grenadines",
	"VE": "Venezuela", "VG": "British Virgin Islands", "VI": "U.S. Virgin Islands", "VN": "Vietnam",
	"VU": "Vanuatu", "WF": "Wallis and Futuna", "WS": "Samoa", "XK": "Kosovo", "YE": "Yemen",
	"YT": "Mayotte", "ZA": "South Africa", "ZM": "Zambia", "ZW": "Zimbabwe",
}

// builtinCountryTable builds the offline table. It knows no networks, only
// which countries each MCC belongs to.
func builtinCountryTable() countryTable {
	tbl := emptyCountryTable()
	tbl.source = CountryTableSourceBuiltin
	for _, entry := range builtinMCCCountries {
		for _, code := range strings.Split(entry.codes, ",") {
			tbl.addCountryMCC(code, entry.mcc, builtinCountryNames[code])
			tbl.mccCountries[entry.mcc] = append(tbl.mccCountries[entry.mcc], code)
		}
	}
	tbl.finish()
	return tbl
}
