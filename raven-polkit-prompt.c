#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <locale.h>
#include "log.h"

/* Logger state for the prompt binary. Default WARN. */
log_level_t g_log_level = LL_WARN;
const char *g_log_prefix = "raven-polkit-prompt";

static GtkWidget *g_entry = NULL;
static GtkWidget *g_entry_label = NULL;
static GtkWidget *g_id_combo = NULL;
static GtkWidget *g_status_label = NULL;
static GtkWidget *g_ok_btn = NULL;
static gboolean g_switching_user = FALSE;

static void show_info_dialog(GtkWindow *parent, const char *msg) {
    GtkWidget *dialog = gtk_message_dialog_new(
        parent,
        GTK_DIALOG_DESTROY_WITH_PARENT | GTK_DIALOG_MODAL,
        GTK_MESSAGE_INFO,
        GTK_BUTTONS_CLOSE,
        "PolicyKit Agent");
    gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(dialog), "%s", msg);
    gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER_ON_PARENT);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

static void response_cb(GtkDialog *dialog, gint response, gpointer data) {
    (void)data;
    if (response == GTK_RESPONSE_OK) {
        const char *password = gtk_entry_get_text(GTK_ENTRY(g_entry));
        printf("P %s\n", password);
        fflush(stdout);
        gtk_entry_set_text(GTK_ENTRY(g_entry), "");
        gtk_widget_set_sensitive(GTK_WIDGET(dialog), FALSE);
    } else {
        exit(1);
    }
}

static void on_id_combo_changed(GtkComboBox *combo, gpointer data) {
    if (g_switching_user) return;

    const char *selected = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(combo));
    if (!selected) return;

    /* Notify daemon that user identity changed */
    printf("U %s\n", selected);
    fflush(stdout);

    gtk_label_set_text(GTK_LABEL(g_status_label), NULL);
    gtk_label_set_text(GTK_LABEL(g_entry_label), "");
    gtk_entry_set_text(GTK_ENTRY(g_entry), "");
    gtk_widget_set_sensitive(g_entry, FALSE);
    if (g_ok_btn) gtk_widget_set_sensitive(g_ok_btn, FALSE);
}

static gboolean on_stdin_readable(GIOChannel *source, GIOCondition condition, gpointer data) {
    if (condition & G_IO_HUP) {
        exit(1);
    }
    
    char *line = NULL;
    gsize len;
    if (g_io_channel_read_line(source, &line, &len, NULL, NULL) == G_IO_STATUS_NORMAL) {
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }

        if (strncmp(line, "M ", 2) == 0) {
            show_info_dialog(GTK_WINDOW(data), line + 2);
        } else if (strncmp(line, "REQ ", 4) == 0) {
            int visibility = (line[4] == '1') ? 1 : 0;
            const char *prompt_str = (len > 6) ? (line + 6) : "Password:";
            gtk_label_set_text(GTK_LABEL(g_entry_label), prompt_str);
            gtk_entry_set_visibility(GTK_ENTRY(g_entry), visibility);
            gtk_widget_set_sensitive(g_entry, TRUE);
            if (g_ok_btn) gtk_widget_set_sensitive(g_ok_btn, TRUE);
            gtk_widget_grab_focus(g_entry);
        } else if (strcmp(line, "DIS") == 0) {
            gtk_widget_set_sensitive(g_entry, FALSE);
            if (g_ok_btn) gtk_widget_set_sensitive(g_ok_btn, FALSE);
        } else if (line[0] == 'E') { // Error / Wrong password
            const char *msg = (len > 2 && line[1] == ' ') ? (line + 2) : "Failed. Wrong password?";
            char *markup = g_markup_printf_escaped("<span foreground='red'><b>%s</b></span>", msg);
            gtk_label_set_markup(GTK_LABEL(g_status_label), markup);
            g_free(markup);

            gtk_widget_set_sensitive(GTK_WIDGET(data), TRUE);
            gtk_entry_set_text(GTK_ENTRY(g_entry), "");
        } else if (line[0] == 'S') { // Success
            exit(0);
        }
        g_free(line);
    }
    return TRUE;
}

static void print_usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s [--message MSG] [--users USER1,USER2] [--user NAME] [--help|-h]\n"
        "\n"
        "  --message MSG   prompt message shown to the user\n"
        "  --users   LIST  comma-separated candidate usernames\n"
        "  --user    NAME  default user to select\n"
        "  --help,   -h    this message\n",
        argv0);
}

int main(int argc, char *argv[]) {
    setlocale(LC_ALL, "");

    const char *message = "Authentication required";
    const char *users_arg = NULL;
    const char *default_user = NULL;

    /* Line-buffered stderr for tail-friendly logs. */
    setvbuf(stderr, NULL, _IOLBF, 0);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--message") == 0 && i + 1 < argc)
            message = argv[++i];
        else if (strcmp(argv[i], "--users") == 0 && i + 1 < argc)
            users_arg = argv[++i];
        else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc)
            default_user = argv[++i];
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    log_debug("prompt starting (default_user=%s)", default_user ? default_user : "<none>");

    gtk_init(&argc, &argv);

    GtkWidget *dialog = gtk_dialog_new_with_buttons(
        "Authentication required",
        NULL,
        GTK_DIALOG_MODAL,
        "_Deny", GTK_RESPONSE_CANCEL,
        "_Allow", GTK_RESPONSE_OK,
        NULL);

    g_ok_btn = gtk_dialog_get_widget_for_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
    gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
    gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
    gtk_window_set_icon_name(GTK_WINDOW(dialog), "dialog-password");

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_set_border_width(GTK_CONTAINER(content), 10);
    gtk_box_set_spacing(GTK_BOX(content), 6);

    /* Subtitle at top with line wrap and subtle styling */
    GtkWidget *msg_label = gtk_label_new(message);
    gtk_label_set_line_wrap(GTK_LABEL(msg_label), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(msg_label), 55);
    gtk_widget_set_halign(msg_label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(content), msg_label, FALSE, FALSE, 4);

    GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(content), sep, FALSE, FALSE, 4);

    /* 2x2 Grid for Identity and Password (matching xfce-polkit grid2x2) */
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 6);

    GtkWidget *combo_label = gtk_label_new("Identity:");
    gtk_widget_set_halign(combo_label, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), combo_label, 0, 0, 1, 1);

    g_id_combo = gtk_combo_box_text_new();
    gtk_widget_set_hexpand(g_id_combo, TRUE);
    gtk_grid_attach(GTK_GRID(grid), g_id_combo, 1, 0, 1, 1);

    /* Populate users into combo box */
    g_switching_user = TRUE;
    int active_idx = 0;
    int cur_idx = 0;

    if (users_arg && *users_arg) {
        char *users_copy = strdup(users_arg);
        char *token = strtok(users_copy, ",");
        while (token) {
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(g_id_combo), token);
            if (default_user && strcmp(token, default_user) == 0) {
                active_idx = cur_idx;
            }
            cur_idx++;
            token = strtok(NULL, ",");
        }
        free(users_copy);
    } else if (default_user) {
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(g_id_combo), default_user);
    }

    gtk_combo_box_set_active(GTK_COMBO_BOX(g_id_combo), active_idx);
    g_switching_user = FALSE;

    g_signal_connect(g_id_combo, "changed", G_CALLBACK(on_id_combo_changed), dialog);

    g_entry_label = gtk_label_new("");
    gtk_widget_set_halign(g_entry_label, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), g_entry_label, 0, 1, 1, 1);

    g_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(g_entry), FALSE);
    gtk_entry_set_activates_default(GTK_ENTRY(g_entry), TRUE);
    gtk_widget_set_hexpand(g_entry, TRUE);
    gtk_widget_set_sensitive(g_entry, FALSE);
    gtk_grid_attach(GTK_GRID(grid), g_entry, 1, 1, 1, 1);

    if (g_ok_btn) gtk_widget_set_sensitive(g_ok_btn, FALSE);

    gtk_box_pack_start(GTK_BOX(content), grid, FALSE, FALSE, 4);

    /* Status Label for error messages */
    g_status_label = gtk_label_new(NULL);
    gtk_label_set_line_wrap(GTK_LABEL(g_status_label), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(g_status_label), 50);
    gtk_widget_set_halign(g_status_label, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(content), g_status_label, FALSE, FALSE, 2);

    gtk_widget_show_all(dialog);

    g_signal_connect(dialog, "response", G_CALLBACK(response_cb), NULL);
    
    GIOChannel *channel = g_io_channel_unix_new(STDIN_FILENO);
    g_io_add_watch(channel, G_IO_IN | G_IO_HUP, on_stdin_readable, dialog);

    gtk_main();
    return 1;
}
