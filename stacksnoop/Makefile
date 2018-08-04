CFLAGS += -Wall

stacksnoop_OBJS := bpf_helpers.o elf_helpers.o event_helpers.o \
                   stacksnoop.o utils.o ksyms.o

ksyms_test_OBJS := ksyms.o ksyms_test.o

.PHONY: all
all: stacksnoop stacksnoop_bpf.o

stacksnoop: $(stacksnoop_OBJS)
	$(CC) -lelf $^ -o $@

stacksnoop_bpf.o: stacksnoop_bpf.c
	clang -O2 -Wall -target bpf -c $^

ksyms_test: $(ksyms_test_OBJS)
	$(CC) $^ -o $@

.PHONY: clean
clean:
	rm -f stacksnoop ksyms_test *.o *.d

# rules

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	$(CC) -M $(CFLAGS) $*.c > $*.d
	@cp -f $*.d $*.d.tmp
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> $*.d
	@rm -f $*.d.tmp

-include $(OBJS:.o=.d)
