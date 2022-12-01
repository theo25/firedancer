CPPFLAGS+=            \
  -pedantic           \
  -Wall               \
  -Wextra             \
  -Wpedantic          \
  -Wstrict-aliasing=2 \
  -Wconversion        \
  -Wdouble-promotion  \
  -Wformat-security

ifdef FD_USING_CLANG

CPPFLAGS+=-Wimplicit-fallthrough

endif

ifdef FD_USING_GCC

CPPFLAGS+=-Wimplicit-fallthrough=2

endif

CFLAGS+=-fsanitize=undefined \
        -fsanitize=shift -fsanitize=shift-exponent -fsanitize=shift-base \
        -fsanitize=integer-divide-by-zero \
        -fsanitize=unreachable \
        -fsanitize=vla-bound \
        -fsanitize=null \
        -fsanitize=return \
        -fsanitize=signed-integer-overflow \
        -fsanitize=bounds \
        -fsanitize=bounds-strict \
        -fsanitize=alignment \
        -fsanitize=object-size \
        -fsanitize=float-divide-by-zero \
        -fsanitize=float-cast-overflow \
        -fsanitize=nonnull-attribute \
        -fsanitize=returns-nonnull-attribute \
        -fsanitize=bool \
        -fsanitize=enum \
        -fsanitize=vptr \
        -fsanitize=pointer-overflow \
        -fsanitize=builtin
CXXFLAGS+=-fsanitize=undefined \
          -fsanitize=shift -fsanitize=shift-exponent -fsanitize=shift-base \
          -fsanitize=integer-divide-by-zero \
          -fsanitize=unreachable \
          -fsanitize=vla-bound \
          -fsanitize=null \
          -fsanitize=return \
          -fsanitize=signed-integer-overflow \
          -fsanitize=bounds \
          -fsanitize=bounds-strict \
          -fsanitize=alignment \
          -fsanitize=object-size \
          -fsanitize=float-divide-by-zero \
          -fsanitize=float-cast-overflow \
          -fsanitize=nonnull-attribute \
          -fsanitize=returns-nonnull-attribute \
          -fsanitize=bool \
          -fsanitize=enum \
          -fsanitize=vptr \
          -fsanitize=pointer-overflow \
          -fsanitize=builtin
