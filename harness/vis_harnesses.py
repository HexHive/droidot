import networkx as nx
import os
import json
import argparse
import pygraphviz as pgv

if os.path.basename(os.getcwd()) == "androlib":
    TARGET_APK_PATH = "target_APK"
else:
    TARGET_APK_PATH = "../target_APK"

def get_short_functionname(mangled_name):
    # from the mangeld java name get only the function name
    if "__" in mangled_name:
        # handle overloaded functions
        mangled_name = mangled_name[:mangled_name.find("__")]
    mangled_name = mangled_name.replace("_1", "#")
    mangled_name = mangled_name[mangled_name.rfind("_")+1:]
    mangled_name = mangled_name.replace("#", "_1")
    return mangled_name


def get_classname(mangled_name):
    # from the mangled java name get the classname
    mangled_name = mangled_name.replace("_1", "#")
    if "__" in mangled_name:
        # handle overloaded functions
        mangled_name = mangled_name[:mangled_name.find("__")]
    mangled_name = mangled_name[:mangled_name.rfind("_")]
    mangled_name = mangled_name.replace("#", "_1")
    return mangled_name

node_color_legend = {
    "final_function" : 'red',
    "phenom_j": 'yellow',
    'cs_heuristic': 'orange',
    'lifecycle': 'blue',
    'in_constructor': 'lightblue',
    'GAPS': 'pink'
}

edge_color_legend = {
    'cs_heuristic_long': 'green',
    'io_matching': 'brown',
    'GAPS': 'pink'
}

arg_color_legend = {
    'io_matching': 'brown',
    'arg_fname_heuristic': 'purple',
    'simple_flowdroid': 'green',
    'phenom_cs': 'blue',
    'simple_special': 'red',
    'GAPS': 'pink'
}

HTML_OUT = """
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
* {
  box-sizing: border-box;
}

.row:after {
  content: "";
  display: table;
  clear: both;
}

/* Create two equal columns that floats next to each other */
.column1 {
  float: left;
  width: 20%;

}

.column2 {
  float: left;
  width: 60%;

}

.column3 {
  float: left;
  width: 20%;
}
.dropdown {
  position: relative;
  display: inline-block;
}

.dropdown-content {
  display: none;
  position: absolute;
  background-color: #f1f1f1;
  min-width: 160px;
  overflow: auto;
  box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2);
  z-index: 1;
}

.dropdown-content a {
  color: black;
  padding: 12px 16px;
  text-decoration: none;
  display: block;
}

.dropdown a:hover {background-color: #ddd;}

.show {display: block;}

</style>
<script>
/* When the user clicks on the button, 
toggle between hiding and showing the dropdown content */
function myFunction(id) {
  document.getElementById(id).classList.toggle("show");
}

// Close the dropdown if the user clicks outside of it
window.onclick = function(event) {
  if (!event.target.matches('.dropbtn')) {
    var dropdowns = document.getElementsByClassName("dropdown-content");
    var i;
    for (i = 0; i < dropdowns.length; i++) {
      var openDropdown = dropdowns[i];
      if (openDropdown.classList.contains('show')) {
        openDropdown.classList.remove('show');
      }
    }
  }
}
</script>
</head>
<body>

<h2>Harness Visualization</h2>
<div class="row">
  <div class="column1">
"""

def cs_sig_2_mangle(cs_sig, data_dependencies):
    out = ""
    out += "<b>"
    out += cs_sig["ret_type"]+"</b>:"
    for i,arg in enumerate(cs_sig["args"]):
        if "constraints" in arg:
            if "lengthof" in arg["constraints"]:
                out += f"""<b style='color:{arg_color_legend[arg['constraints']['lengthof']['reason']]}'>{arg['type']}(lengtof[{arg['constraints']['lengthof']['bytearr_arg']}])</b>,"""
                continue
            elif "equals" in arg["constraints"]:
                out += f"""<b style='color:{arg_color_legend[arg['constraints']['equals']['reason']]}'>""" + arg["constraints"]["equals"]["value"]+"</b>,"
                continue
            elif "filedescriptor" in arg["constraints"]:
                out += f"""<b style='color:{arg_color_legend[arg['constraints']['filedescriptor']['reason']]}'>{arg['type']}(filedescriptor)</b>,"""
                continue
            elif "filepath" in arg["constraints"]:
                out += f"""<b style='color:{arg_color_legend[arg['constraints']['filepath']['reason']]}'>{arg['type']}(filepath)</b>,"""
                continue
            elif "empty_array" in arg["constraints"]:
                out += f"""<b style='color:{arg_color_legend[arg['constraints']['empty_array']['reason']]}'>{arg['type']}(empty_array)</b>,"""
                continue
            elif "same_var" in arg["constraints"]:
                out += f"""<b style='color:{arg_color_legend[arg['constraints']['same_var']['reason']]}'>{arg['type']}(same_var)</b>,"""
                continue
            elif "stdlib" in arg["constraints"]:
                out += f"""<b style='color:{arg_color_legend[arg['constraints']['stdlib']['reason']]}'>{arg['type']}(stdlib)</b>,"""
                continue
            elif "max_array_length" in arg["constraints"]:
                out += f"""<b style='color:{arg_color_legend[arg['constraints']['max_array_length']['reason']]}'>{arg['type']}(max_array_length)</b>,"""
                continue
            elif "byte_buffer_lenght" in arg["constraints"]:
                out += f"""<b style='color:{arg_color_legend[arg['constraints']['byte_buffer_lenght']['reason']]}'>{arg['type']}(byte_buffer_lenght)</b>,"""
                continue
            else:
                out += f"<b>{arg['type']}({arg['constraints']})</b>,"
                continue
        if str(i) in data_dependencies:
            out += f"""<b style='color:{arg_color_legend[data_dependencies[str(i)]['reason']]}'>""" + arg["type"] +f"</b>,"
            continue
        out += "<b>" + arg["type"]+"</b>,"
    out = out.replace("'", "\\'")
    out = out.replace("\"", "&quot;")
    return out


def draw_harness_graphs(app):
    cs_json_path = os.path.join(TARGET_APK_PATH, app, "harness_generation_callsequences.json")
    if not os.path.exists(cs_json_path):
        print("[!] no json found, skipping")
        return
    with open(cs_json_path, "r") as f:
        cs_json = json.loads(f.read())
    output_path = os.path.join(TARGET_APK_PATH, app, "harness_vis")
    if not os.path.exists(output_path):
        os.mkdir(output_path)
    flist =[]
    f2sigs = {}
    for f in cs_json:
        if "_nocov" in f:
            continue
        G = pgv.AGraph(strict=False, directed=True)
        f_prev = None
        color_map = []
        for i,fn in enumerate(cs_json[f]):
            name = fn["name"]
            reason = fn["reason"]
            color_map.append(node_color_legend[reason])
            G.add_node(i, label=get_short_functionname(name), color=node_color_legend[reason])
            if f_prev is None:
                f_prev = i
                f2sigs[f] = name + " " + cs_sig_2_mangle(cs_json[f][i]["signature"], cs_json[f][i]["data_dependencies"]) + "<br>"
                continue
            f2sigs[f] =  f2sigs[f] + name + " " + cs_sig_2_mangle(cs_json[f][i]["signature"], cs_json[f][i]["data_dependencies"]) + "<br>"
            #G.add_edges_from([(f_prev, i)])
            G.add_edge(f_prev, i)
            f_prev = i
            for arg_ind in fn["data_dependencies"]:
                ind = fn["data_dependencies"][arg_ind]["findex"]
                reason = fn["data_dependencies"][arg_ind]["reason"]
                #G.add_edges_from([(int(ind), i)], color=edge_color_legend[reason])
                G.add_edge(int(ind), i, key=f'{name}-{arg_ind}', color=edge_color_legend[reason])
                #G.add_edge(int(ind), i)
        
        G.layout("dot") 
        G.draw(os.path.join(output_path, f'{f}.png'))
        flist.append(f)

    # generate legend
    G = pgv.AGraph(strict=False, directed=True)
    c = 0
    prev = None
    for i in node_color_legend: 
        G.add_node(i, label=i, color=node_color_legend[i])
        if c % 3 == 0 and prev:
            G.add_edge(prev, i, style='invis')
        prev = i

    G.add_node("inv3", style='invis')
    G.add_node("inv4", style='invis')
    G.add_edge("inv3", "inv4", label='cfg order')
    G.add_node("inv6", style='invis')
    G.add_node("inv7", style='invis')
    G.add_edge("inv6", "inv7", label='io_matching', color='brown')
    G.layout("dot") 
    G.draw(os.path.join(output_path, f'legend.png'))

    buttons = ""
    curr_path = os. getcwd()

    class2flist = {}
    for f in flist:
        cls = get_classname(f)
        if cls in class2flist:
            class2flist[cls].append(f)
        else:
            class2flist[cls] = [f]

    for i,cls in enumerate(class2flist):
        buttons += f"""<button onclick="myFunction('dropdown_{i}')" class="dropbtn">{cls}</button>\n"""
        buttons += f"""<div id="dropdown_{i}" class="dropdown-content">\n"""
        for f in class2flist[cls]:
            outpath = os.path.join(curr_path, TARGET_APK_PATH, app, "harness_vis", f+'.png')
            buttons += f"""<button onclick="javascript:document.getElementById('graph_disp').src='file:///{outpath}';document.getElementById('sig_list').innerHTML='{f2sigs[f]}'">{get_short_functionname(f)}</button><br>\n"""
        buttons += "</div><br>"


    #for f in flist:
    #    outpath = os.path.join(curr_path, TARGET_APK_PATH, app, "harness_vis", f+'.png')
    #    buttons += f"""<button onclick="javascript:document.getElementById('graph_disp').src='file:///{outpath}';document.getElementById('sig_list').innerHTML='{f2sigs[f]}'">{f}</button><br>\n"""


    if len(flist) == 0:
        # no functions are present 
        html_out = f"<p>no functions in the callsequence json</p>please check {os.path.join(curr_path, TARGET_APK_PATH, app, 'signatures_libraries_offsets.txt')}"
    else:
        sig_list = f2sigs[flist[0]]

        img_p = os.path.join(curr_path, TARGET_APK_PATH, app, "harness_vis", flist[0]+'.png')
        leg_p = os.path.join(curr_path, TARGET_APK_PATH, app, "harness_vis", 'legend.png')
        arg_legend = ""
        for c in arg_color_legend:
            arg_legend += f"<b style='color:{arg_color_legend[c]}'>{c}</b><br>"
        img = f"""</div>
    <div class="column2">
        <img id=graph_disp src="{img_p}">
        <p id=sig_list>
    {sig_list}
    </p>
    </div>
    <div class="column3">
        <img src="{leg_p}"><br>
        <b>arguments</b><br>
        {arg_legend}
    </div>
    </div>
    </html>
    """
        html_out = HTML_OUT + buttons + img
    with open(os.path.join(output_path, f"{app}.html"), "w") as f:
        f.write(html_out)

    print("######################################################")
    print(f'view the harnesses at file://{os.path.join(curr_path, TARGET_APK_PATH, app, "harness_vis", f"{app}.html")}')
    print("######################################################")


if __name__ == "__main__":

    """output = generate_argument_constraints_simple("hellolibs")
    callsequence = generate_empty_callsequence("hellolibs")
    output2 = generate_callsequence_simple("hellolibs", callsequence)
    harness_callsequences = parse_static("hellolibs", False, False, False, False, False)"""

    parser = argparse.ArgumentParser(description=f'for an apk, uses the information in harness_geneartion.json to create a graph and a webpage to view the output')
    parser.add_argument("--target", type=str, required=True, help="name of app for which to generate harness visualizers")
    args = parser.parse_args()    

    draw_harness_graphs(args.target)



"""
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
* {
  box-sizing: border-box;
}

/* Create two equal columns that floats next to each other */
.column1 {
  float: left;
  width: 20%;

}

.column2 {
  float: right;
  width: 80%;

}

/* Clear floats after the columns */
.row:after {
  content: "";
  display: table;
  clear: both;
}
</style>
</head>
<body>

<h2>Harness Visualization</h2>

  <div class="column1">
    <button onclick="javascript:document.getElementById('graph_disp').src='asdf'">FNMAE</button>
  </div>
  <div class="column2">
    <img id=graph_disp src="https://www.anti-bias.eu/wp-content/uploads/2015/01/shutterstock_92612287-e1420280083718.jpg">
  </div>

</body>
</html>
"""