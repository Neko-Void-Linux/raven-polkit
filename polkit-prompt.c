#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <locale.h>
#include "log.h"

/* Logger state for the prompt binary. Default WARN. */
log_level_t g_log_level = LL_WARN;
const char *g_log_prefix = "polkit-prompt";

static GtkWidget *entry = NULL;

static void response_cb(GtkDialog *dialog, gint response, gpointer data) {
    (void)data;
    if (response == GTK_RESPONSE_OK) {
        const char *password = gtk_entry_get_text(GTK_ENTRY(entry));
        printf("%s\n", password);
        fflush(stdout);
        exit(0);
    }
    exit(1);
}

static void print_usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s [--message MSG] [--user NAME] [--help|-h]\n"
        "\n"
        "  --message MSG   prompt message shown to the user\n"
        "  --user  NAME    user being authenticated (display only)\n"
        "  --help, -h      this message\n",
        argv0);
}

int main(int argc, char *argv[]) {
    setlocale(LC_ALL, "");

    const char *message = "Authentication required";
    const char *user = NULL;

    /* Line-buffered stderr for tail-friendly logs. */
    setvbuf(stderr, NULL, _IOLBF, 0);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--message") == 0 && i + 1 < argc)
            message = argv[++i];
        else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc)
            user = argv[++i];
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    log_debug("prompt starting (user=%s)", user ? user : "<none>");

    gtk_init(&argc, &argv);

    GtkWidget *dialog = gtk_dialog_new_with_buttons(
        "Authentication",
        NULL,
        GTK_DIALOG_MODAL,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_OK", GTK_RESPONSE_OK,
        NULL);

    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
    gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
    gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 8);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 12);

    GtkWidget *icon = gtk_image_new_from_icon_name("dialog-password",
                                                     GTK_ICON_SIZE_DIALOG);
    gtk_grid_attach(GTK_GRID(grid), icon, 0, 0, 1, 2);

    char *markup = g_markup_printf_escaped("<b>%s</b>", message);
    GtkWidget *label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label), markup);
    g_free(markup);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(label), 50);
    gtk_grid_attach(GTK_GRID(grid), label, 1, 0, 1, 1);

    if (user) {
        char *user_markup = g_markup_printf_escaped(
            "Authenticating as: <b>%s</b>", user);
        GtkWidget *user_label = gtk_label_new(NULL);
        gtk_label_set_markup(GTK_LABEL(user_label), user_markup);
        g_free(user_markup);
        gtk_grid_attach(GTK_GRID(grid), user_label, 1, 1, 1, 1);
    }

    GtkWidget *pass_label = gtk_label_new("Password:");
    gtk_grid_attach(GTK_GRID(grid), pass_label, 0, 2, 1, 1);

    entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    gtk_widget_set_hexpand(entry, TRUE);
    gtk_grid_attach(GTK_GRID(grid), entry, 1, 2, 1, 1);

    gtk_container_add(GTK_CONTAINER(content), grid);
    gtk_widget_show_all(dialog);

    g_signal_connect(dialog, "response", G_CALLBACK(response_cb), NULL);

    gtk_main();
    return 1;
}
