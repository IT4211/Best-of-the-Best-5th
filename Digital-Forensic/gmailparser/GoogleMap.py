import urllib

def get_googlemap(gmap_markers, path):
    google_api_key = "AIzaSyDg95GEcldj4-x950NFMrzI0d5r_Gm0jrE"
    center = gmap_markers[0]
    markers = "|".join(gmap_markers)

    google_map_url = "https://maps.googleapis.com/maps/api/staticmap?" \
                     "center= "+ center +"&zoom=2&size=600x600&format=png&visual_refresh=true" \
                     "&markers = color:red"+ markers +"|" \
                     "&path=color:red|weight:2|"+markers+"" \
                     "&key=" + google_api_key + ""

    gmaps = "gmap.jpg"
    urllib.urlretrieve(google_map_url, path + gmaps)