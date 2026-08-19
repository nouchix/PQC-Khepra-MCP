
with open("pkg/mcp/transport_http.go", "r") as f:
    s = f.read()

s = s.replace('var firstTime, lastTime string', 'var firstTime, lastTime int64')
s = s.replace('firstTime == ""', 'firstTime == 0')
s = s.replace('lastTime == ""', 'lastTime == 0')
s = s.replace('fmt.Fprintf(w, `{"node_count":%d,"first_node_time":%q,"last_node_time":%q,"dag_store":"active"}`,', 'fmt.Fprintf(w, `{"node_count":%d,"first_node_time":%d,"last_node_time":%d,"dag_store":"active"}`,')

with open("pkg/mcp/transport_http.go", "w") as f:
    f.write(s)
