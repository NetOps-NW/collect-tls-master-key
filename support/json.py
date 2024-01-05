
from support.logger import logger;
import json;
import os;
import jsonschema;
import sys;

def from_json(path="", str=""):
    if path:
        if os.path.exists(path):
            with open(path, "r") as file:
                return json.load(file);
        else:
            logger.error(f"Path {path} doesn't exist.");
    else:
        return json.loads(str);

def to_json(object=dict(), path=""):
    if path:
        with open(path, "w") as file:
            json.dump(object, file, indent=4);
    else:
        return json.dumps(object, indent=4);

def validate_json_schema(instance_path, schema_path):
    instance, schema = from_json(path=instance_path), from_json(path=schema_path);
    try:
        jsonschema.validate(instance, schema, format_checker=jsonschema.FormatChecker);
        return;
    except jsonschema.exceptions.ValidationError as err:
        logger.critical(f"Validation Error - {err.message}");
        logger.critical(f"Validation Error - {jsonschema._utils.format_as_index(err.relative_path)}");
    except jsonschema.exceptions.SchemaError as err:
        logger.critical(f"Schema Error - {err.message}");
        logger.critical(f"Schema Error - {jsonschema._utils.format_as_index(err.relative_path)}");
    sys.exit(1);
