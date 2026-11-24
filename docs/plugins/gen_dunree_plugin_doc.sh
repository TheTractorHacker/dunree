#!/bin/bash

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# Cd into the Dunree plugin SDK directory
cd "${SCRIPT_DIR}"/../../src/mod/plugins/dunree_plugin/

# Add header to the documentation
echo "# Dunree Plugin APIs" >docs.md
echo "This API documentation is auto-generated from the Dunree plugin source code." >>docs.md
echo "" >>docs.md
echo "" >>docs.md
echo "<pre><code class='language-go'>" >>docs.md
go doc -all >>docs.md
echo "</code></pre>" >>docs.md

# Replace // import "github.com/foleyit/dunree/mod/plugins/dunree_plugin" with
# // import "{{your_module_package_name_in_go.mod}}/mod/plugins/dunree_plugin"
sed -i 's|// import "github.com/foleyit/dunree/mod/plugins/dunree_plugin"|// import "{{your_module_package_name_in_go.mod}}/mod/plugins/dunree_plugin"|g' docs.md

# Move the generated docs to the plugins/html directory
mv docs.md "../../../../docs/plugins/docs/dunree_plugin API.md"

echo "Done generating Dunree plugin documentation."
