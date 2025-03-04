ifdef FD_HAS_HOSTED
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_X86
ifdef FD_HAS_DOUBLE

.PHONY: fdctl cargo

$(call add-objs,main1 config caps utility topology keygen ready info run/run run/tiles/tiles run/tiles/fd_net run/tiles/fd_netmux run/tiles/fd_dedup run/tiles/fd_pack run/tiles/fd_quic run/tiles/fd_verify run/tiles/fd_bank run/tiles/fd_shred run/tiles/fd_store monitor/monitor monitor/helper configure/configure configure/large_pages configure/sysctl configure/shmem configure/xdp configure/xdp_leftover configure/ethtool configure/workspace_leftover configure/workspace,fd_fdctl)
$(call make-bin-rust,fdctl,main,fd_fdctl fd_disco fd_flamenco fd_ip fd_reedsol fd_ballet fd_tango fd_util fd_quic solana_validator)
$(OBJDIR)/obj/app/fdctl/configure/xdp.o: src/tango/xdp/fd_xdp_redirect_prog.o
$(OBJDIR)/obj/app/fdctl/config.o: src/app/fdctl/config/default.toml

# Phony target to always rerun cargo build ... it will detect if anything
# changed on the library side.
cargo:

# Cargo build cannot cache the prior build if the command line changes,
# for example if we did,
#
#  1. cargo build --release --lib -p solana-validator
#  2. cargo build --release --lib -p solana-genesis
#  3. cargo build --release --lib -p solana-validator
#
# The third build would rebuild from some partial state. This is not
# great for build times, so we always build all the libs and bins
# with one cargo command, even if the dependency could be more fine
# grained.
ifeq ($(RUST_PROFILE),release)
cargo:
	cd ./solana && env --unset=LDFLAGS ./cargo build --release --lib -p solana-validator -p solana-genesis -p solana-cli --bin solana
else
cargo:
	cd ./solana && env --unset=LDFLAGS ./cargo build --lib -p solana-validator -p solana-genesis -p solana-cli --bin solana
endif

solana/target/$(RUST_PROFILE)/libsolana_validator.a: cargo

solana/target/$(RUST_PROFILE)/solana: cargo

$(OBJDIR)/lib/libsolana_validator.a: solana/target/$(RUST_PROFILE)/libsolana_validator.a
	$(MKDIR) $(dir $@) && cp solana/target/$(RUST_PROFILE)/libsolana_validator.a $@

fdctl: $(OBJDIR)/bin/fdctl

$(OBJDIR)/bin/solana: solana/target/$(RUST_PROFILE)/solana
	$(MKDIR) $(dir $@) && cp solana/target/$(RUST_PROFILE)/solana $@

rust: $(OBJDIR)/bin/solana

endif
endif
endif
endif
