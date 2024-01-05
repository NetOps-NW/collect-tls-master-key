
from support import logger, from_json;
import sys;

def collect_master_key(capture_path):
    with open(capture_path.replace(".json", ".key"), "w") as file:
        for packet in from_json(capture_path):
            if "_source" in packet:
                if "layers" in packet["_source"]:
                    if "f5ethtrailer" in packet["_source"]["layers"]:
                        if "f5ethtrailer.tls.data" in packet["_source"]["layers"]["f5ethtrailer"]:
                            if "f5ethtrailer.tls.keylog" in packet["_source"]["layers"]["f5ethtrailer"]["f5ethtrailer.tls.data"]:
                                file.write(packet["_source"]["layers"]["f5ethtrailer"]["f5ethtrailer.tls.data"]["f5ethtrailer.tls.keylog"] + "\n");

if "__main__" in __name__:
    if len(sys.argv[1:]) == 1:
        collect_master_key(sys.argv[1]);
    else:
        logger.error(f"Usage: {sys.argv[0]} capture_path.json");
        sys.exit(1);
