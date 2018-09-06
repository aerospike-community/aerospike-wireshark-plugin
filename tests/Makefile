TEST_CASES = $(wildcard *.pdml)

TSHARK_EXECUTABLE?=tshark

check_output = @(echo -n "Testing $(notdir $1)" && cd $(dir $1) && \
		$(TSHARK_EXECUTABLE) -T pdml -X lua_script:../lua/aerospike.lua -r $(subst .pdml,,$(notdir $1)) > $(notdir $2) 2>&1 && \
		xsltproc filter.xsl $(notdir $2)  | diff $(notdir $1) - ) && echo " ... [OK]"

all: test

coverage:
	@echo "Running Wireshark with test captures ...\n"
	for i in *.pcapng; do \
		wireshark -r $$i -X lua_script:../lua/aerospike.lua & sleep 6; wmctrl -c $$i ; \
	done
	sleep 3
	@echo "\nGenerate report using luacov-console ...\n"
	luacov-console ../lua
	luacov-console -s --no-colored

%.pdml.current: %.pdml %
	$(call check_output, $<, $@)

test: $(TEST_CASES:.pdml=.pdml.current)

clean:
	@rm -f $(TEST_CASES:.pdml=.pdml.current)
	@rm -f *~ luacov.*

.PHONY: clean
