#include "cli.h"

/*
 * main
 *   Thin wrapper that forwards execution to cli_run().
 * Returns the CLI dispatcher status code.
 */
int main(int argc, char **argv) {
    return cli_run(argc, argv);
}
