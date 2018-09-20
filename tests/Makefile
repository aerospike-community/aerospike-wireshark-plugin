TEST_CASES = $(wildcard *.pdml)

TSHARK_EXECUTABLE?=tshark

check_output = @(echo -n "Testing $(notdir $1)" && cd $(dir $1) && \
		TEST=true $(TSHARK_EXECUTABLE) -2 -T pdml -X lua_script:../lua/aerospike.lua -r $(subst .pdml,,$(notdir $1)) > $(notdir $2) 2>&1 && \
		xsltproc filter.xsl $(notdir $2)  | diff $(notdir $1) - ) && echo " ... [OK]"

all: test

%.pdml.current: %.pdml %
	$(call check_output, $<, $@)

test: $(TEST_CASES:.pdml=.pdml.current)
	@echo "\nGenerate report using luacov-console ...\n"
	luacov-console ../lua
	luacov-console -s --no-colored

clean:
	@rm -f $(TEST_CASES:.pdml=.pdml.current)
	@rm -f *~ luacov.*

.PHONY: clean
