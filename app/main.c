/*
 * WireGuard Server ACAP entry binary.
 *
 * Owns the manifest.json parameters, serves them on 127.0.0.1:2211
 * (behind the authenticated reverse proxy as /local/WireGuard_Server/api/settings, so
 * settings work on devices without /axis-cgi/param.cgi) and supervises the
 * lib/WireGuard_Serverd service, restarting it on parameter change or exit.
 * The service always runs, even with the server disabled, because it also
 * serves the status API (and the server public key) to the settings page.
 * The loopback port must be unique per device; see PARAM_CGI_FALLBACK.md.
 */

#include <axsdk/axparameter.h>
#include <gio/gio.h>
#include <glib-unix.h>
#include <glib/gstdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define APP_NAME "WireGuard_Server"
#define APP_DIR "/usr/local/packages/" APP_NAME
#define SERVICE_BINARY APP_DIR "/lib/" APP_NAME "d"
#define SETTINGS_HTTP_PORT 2211
#define RESTART_DELAY_MS 2000
/* The Peers parameter grows with every client, so allow a large settings POST. */
#define MAX_REQUEST 65536

typedef struct {
    const char *name;
    const char *fallback;
    gboolean secret;
    /* Only used by the settings page to build client configs: changing it must
     * not restart the service, which would drop every connected peer. */
    gboolean ui_only;
    char *value;
} Parameter;

/* Must stay in sync with paramConfig in manifest.json. */
// clang-format off
static Parameter parameters[] = {
    {"Enabled",        "no",           FALSE, FALSE, NULL},
    {"PrivateKey",     "",             TRUE,  FALSE, NULL},
    {"ListenPort",     "51820",        FALSE, FALSE, NULL},
    {"Address",        "10.66.0.1/24", FALSE, FALSE, NULL},
    {"Peers",          "",             FALSE, FALSE, NULL},
    {"RouteSubnets",   "",             FALSE, FALSE, NULL},
    {"PeerToPeer",     "no",           FALSE, FALSE, NULL},
    {"MTU",            "1420",         FALSE, FALSE, NULL},
    {"PublicEndpoint", "",             FALSE, TRUE,  NULL},
    {"ClientDNS",      "",             FALSE, TRUE,  NULL},
};
// clang-format on

static AXParameter *parameter_handle;
static GMainLoop *main_loop;
static GPid service_pid = -1;
static guint restart_timer;
static gboolean shutting_down;

static Parameter *find_parameter(const char *name) {
    for (gsize i = 0; i < G_N_ELEMENTS(parameters); i++) {
        if (g_strcmp0(parameters[i].name, name) == 0)
            return &parameters[i];
    }
    return NULL;
}

/* Parameter callbacks report a qualified name such as root.APPNAME.Enabled. */
static Parameter *find_parameter_suffix(const char *qualified_name) {
    const char *last = strrchr(qualified_name, '.');
    return find_parameter(last ? last + 1 : qualified_name);
}

static const char *parameter_value(const char *name) {
    Parameter *parameter = find_parameter(name);
    if (!parameter)
        return "";
    return parameter->value ? parameter->value : parameter->fallback;
}

static void load_parameter(Parameter *parameter) {
    GError *error = NULL;
    gchar *value = NULL;

    if (ax_parameter_get(parameter_handle, parameter->name, &value, &error)) {
        g_free(parameter->value);
        parameter->value = g_strdup(value ? value : "");
        g_free(value);
    } else {
        syslog(LOG_WARNING, "read parameter %s failed: %s", parameter->name, error ? error->message : "unknown error");
        if (!parameter->value)
            parameter->value = g_strdup(parameter->fallback);
    }
    g_clear_error(&error);
}

static void start_service(void);

static gboolean on_restart_timeout(gpointer user_data) {
    (void)user_data;
    restart_timer = 0;
    start_service();
    return G_SOURCE_REMOVE;
}

static void schedule_restart(void) {
    if (shutting_down || restart_timer)
        return;
    restart_timer = g_timeout_add(RESTART_DELAY_MS, on_restart_timeout, NULL);
}

static void on_service_exit(GPid pid, gint status, gpointer user_data) {
    (void)user_data;
    g_spawn_close_pid(pid);
    service_pid = -1;
    syslog(LOG_INFO, "service exited with status %d", status);
    schedule_restart();
}

static void stop_service(void) {
    if (service_pid > 0)
        kill(service_pid, SIGTERM);
}

static void start_service(void) {
    GError *error = NULL;
    gchar **envp = NULL;
    gchar *argv[] = {(gchar *)SERVICE_BINARY, NULL};

    if (shutting_down || service_pid > 0)
        return;
    if (g_access(SERVICE_BINARY, X_OK) != 0)
        return; /* C-only package: no service binary to supervise. */

    envp = g_get_environ();
    for (gsize i = 0; i < G_N_ELEMENTS(parameters); i++) {
        gchar *upper = g_ascii_strup(parameters[i].name, -1);
        gchar *key = g_strconcat("ACAP_", upper, NULL);
        envp = g_environ_setenv(envp, key, parameter_value(parameters[i].name), TRUE);
        g_free(key);
        g_free(upper);
    }

    if (g_spawn_async(APP_DIR, argv, envp, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &service_pid, &error)) {
        syslog(LOG_INFO, "started service pid %d", (int)service_pid);
        g_child_watch_add(service_pid, on_service_exit, NULL);
    } else {
        syslog(LOG_ERR, "failed to start service: %s", error ? error->message : "unknown error");
        service_pid = -1;
        schedule_restart();
    }

    g_clear_error(&error);
    g_strfreev(envp);
}

static void apply_configuration(void) {
    if (service_pid > 0)
        stop_service(); /* The child watch restarts it with the new values. */
    else
        start_service();
}

static void on_parameter_changed(const gchar *name, const gchar *value, gpointer user_data) {
    (void)user_data;
    Parameter *parameter = find_parameter_suffix(name);
    if (!parameter)
        return;
    if (g_strcmp0(parameter->value, value) == 0)
        return;

    g_free(parameter->value);
    parameter->value = g_strdup(value ? value : "");
    syslog(LOG_INFO, "parameter %s changed", parameter->name);
    if (!parameter->ui_only)
        apply_configuration();
}

/* ---------------------------------------------------------------- settings */

static void json_append_escaped(GString *out, const char *value) {
    for (const char *cursor = value ? value : ""; *cursor; cursor++) {
        switch (*cursor) {
        case '"':
            g_string_append(out, "\\\"");
            break;
        case '\\':
            g_string_append(out, "\\\\");
            break;
        case '\n':
            g_string_append(out, "\\n");
            break;
        case '\r':
            g_string_append(out, "\\r");
            break;
        case '\t':
            g_string_append(out, "\\t");
            break;
        default:
            if ((unsigned char)*cursor < 0x20)
                g_string_append_printf(out, "\\u%04x", (unsigned char)*cursor);
            else
                g_string_append_c(out, *cursor);
        }
    }
}

/* Secrets are never returned; the UI only learns whether one is stored. */
static gchar *settings_json(void) {
    GString *out = g_string_new("{");

    for (gsize i = 0; i < G_N_ELEMENTS(parameters); i++) {
        const char *value = parameter_value(parameters[i].name);
        if (i)
            g_string_append_c(out, ',');
        g_string_append_c(out, '"');
        json_append_escaped(out, parameters[i].name);
        g_string_append(out, "\":\"");
        if (!parameters[i].secret)
            json_append_escaped(out, value);
        g_string_append_c(out, '"');
        if (parameters[i].secret) {
            g_string_append(out, ",\"");
            json_append_escaped(out, parameters[i].name);
            g_string_append_printf(out, "IsSet\":\"%s\"", *value ? "yes" : "no");
        }
    }

    g_string_append_c(out, '}');
    /* g_string_free(out, FALSE) inlines to g_string_free_and_steal() on newer
     * headers and breaks on AXIS OS 11.x runtimes; copy the buffer instead. */
    gchar *json = g_strdup(out->str);
    g_string_free(out, TRUE);
    return json;
}

static gchar *url_decode(const char *value, gsize length) {
    GString *out = g_string_sized_new(length);

    for (gsize i = 0; i < length; i++) {
        if (value[i] == '+') {
            g_string_append_c(out, ' ');
        } else if (value[i] == '%' && i + 2 < length && g_ascii_isxdigit(value[i + 1]) &&
                   g_ascii_isxdigit(value[i + 2])) {
            g_string_append_c(out,
                              (gchar)(g_ascii_xdigit_value(value[i + 1]) * 16 + g_ascii_xdigit_value(value[i + 2])));
            i += 2;
        } else {
            g_string_append_c(out, value[i]);
        }
    }

    gchar *decoded = g_strdup(out->str);
    g_string_free(out, TRUE);
    return decoded;
}

/* Applies an application/x-www-form-urlencoded body, ignoring unknown keys. */
static gboolean apply_settings_body(const char *body) {
    gchar **pairs = g_strsplit(body ? body : "", "&", -1);
    gboolean changed = FALSE;

    for (gchar **pair = pairs; *pair; pair++) {
        gchar *separator = strchr(*pair, '=');
        if (!separator)
            continue;

        gchar *name = url_decode(*pair, (gsize)(separator - *pair));
        gchar *value = url_decode(separator + 1, strlen(separator + 1));
        Parameter *parameter = find_parameter(name);
        GError *error = NULL;

        if (!parameter) {
            syslog(LOG_WARNING, "rejected unknown parameter %s", name);
        } else if (g_strcmp0(parameter->value, value) == 0) {
            /* No change. */
        } else if (ax_parameter_set(parameter_handle, parameter->name, value, TRUE, &error)) {
            g_free(parameter->value);
            parameter->value = g_strdup(value);
            if (!parameter->ui_only)
                changed = TRUE;
        } else {
            syslog(LOG_ERR, "write parameter %s failed: %s", parameter->name, error ? error->message : "unknown error");
        }

        g_clear_error(&error);
        g_free(name);
        g_free(value);
    }

    g_strfreev(pairs);
    return changed;
}

static void send_response(GOutputStream *out, const char *status, const char *content_type, const char *body) {
    gchar *response = g_strdup_printf("HTTP/1.1 %s\r\n"
                                      "Content-Type: %s\r\n"
                                      "Content-Length: %zu\r\n"
                                      "Cache-Control: no-store\r\n"
                                      "Connection: close\r\n"
                                      "\r\n"
                                      "%s",
                                      status, content_type, strlen(body), body);
    g_output_stream_write_all(out, response, strlen(response), NULL, NULL, NULL);
    g_free(response);
}

static gboolean on_settings_request(GSocketService *service, GSocketConnection *connection, GObject *source,
                                    gpointer user_data) {
    (void)service;
    (void)source;
    (void)user_data;

    GInputStream *in = g_io_stream_get_input_stream(G_IO_STREAM(connection));
    GOutputStream *out = g_io_stream_get_output_stream(G_IO_STREAM(connection));
    gchar buffer[MAX_REQUEST];
    gsize total = 0;
    gsize header_length = 0;
    glong content_length = 0;

    while (total < sizeof(buffer) - 1) {
        gssize got = g_input_stream_read(in, buffer + total, sizeof(buffer) - 1 - total, NULL, NULL);
        if (got <= 0)
            break;
        total += (gsize)got;
        buffer[total] = '\0';

        gchar *header_end = strstr(buffer, "\r\n\r\n");
        if (!header_end)
            continue;
        header_length = (gsize)(header_end - buffer) + 4;

        if (content_length == 0) {
            gchar *headers = g_ascii_strdown(buffer, (gssize)header_length);
            gchar *field = strstr(headers, "content-length:");
            if (field)
                content_length = strtol(field + strlen("content-length:"), NULL, 10);
            g_free(headers);
        }
        if (total - header_length >= (gsize)content_length)
            break;
    }

    if (header_length == 0) {
        send_response(out, "400 Bad Request", "text/plain", "bad request\n");
    } else {
        gboolean is_get = g_str_has_prefix(buffer, "GET ");
        gboolean is_post = g_str_has_prefix(buffer, "POST ");
        gchar *line_end = strstr(buffer, "\r\n");
        gchar *request_line = g_strndup(buffer, (gsize)(line_end - buffer));
        gboolean is_settings = strstr(request_line, "settings") != NULL;

        if (is_get && is_settings) {
            gchar *json = settings_json();
            send_response(out, "200 OK", "application/json", json);
            g_free(json);
        } else if (is_post && is_settings) {
            gchar *body = g_strndup(buffer + header_length, total - header_length);
            gboolean changed = apply_settings_body(body);
            g_free(body);
            send_response(out, "200 OK", "application/json", "{\"status\":\"ok\"}");
            if (changed)
                apply_configuration();
        } else {
            send_response(out, "404 Not Found", "text/plain", "not found\n");
        }

        g_free(request_line);
    }

    g_io_stream_close(G_IO_STREAM(connection), NULL, NULL);
    return TRUE;
}

static gboolean start_settings_server(void) {
    GError *error = NULL;
    GSocketService *service = g_socket_service_new();
    GInetAddress *address = g_inet_address_new_loopback(G_SOCKET_FAMILY_IPV4);
    GSocketAddress *socket_address = g_inet_socket_address_new(address, SETTINGS_HTTP_PORT);
    gboolean added = g_socket_listener_add_address(G_SOCKET_LISTENER(service), socket_address, G_SOCKET_TYPE_STREAM,
                                                   G_SOCKET_PROTOCOL_TCP, NULL, NULL, &error);

    g_object_unref(socket_address);
    g_object_unref(address);

    if (!added) {
        /* A failure here usually means another ACAP already claimed the port,
         * which would silently forward this app's API to that app. */
        syslog(LOG_ERR, "settings server cannot bind 127.0.0.1:%d: %s", SETTINGS_HTTP_PORT,
               error ? error->message : "unknown error");
        g_clear_error(&error);
        g_object_unref(service);
        return FALSE;
    }

    g_signal_connect(service, "incoming", G_CALLBACK(on_settings_request), NULL);
    g_socket_service_start(service);
    syslog(LOG_INFO, "settings server listening on 127.0.0.1:%d", SETTINGS_HTTP_PORT);
    return TRUE;
}

/* -------------------------------------------------------------------- main */

static gboolean on_terminate(gpointer user_data) {
    (void)user_data;
    shutting_down = TRUE;
    stop_service();
    g_main_loop_quit(main_loop);
    return G_SOURCE_REMOVE;
}

int main(void) {
    GError *error = NULL;

    openlog(APP_NAME, LOG_PID, LOG_USER);

    parameter_handle = ax_parameter_new(APP_NAME, &error);
    if (!parameter_handle) {
        syslog(LOG_ERR, "ax_parameter_new failed: %s", error ? error->message : "unknown error");
        g_clear_error(&error);
        return EXIT_FAILURE;
    }

    for (gsize i = 0; i < G_N_ELEMENTS(parameters); i++) {
        load_parameter(&parameters[i]);
        if (!ax_parameter_register_callback(parameter_handle, parameters[i].name, on_parameter_changed, NULL, &error)) {
            syslog(LOG_WARNING, "callback for %s failed: %s", parameters[i].name,
                   error ? error->message : "unknown error");
        }
        g_clear_error(&error);
    }

    main_loop = g_main_loop_new(NULL, FALSE);
    g_unix_signal_add(SIGTERM, on_terminate, NULL);
    g_unix_signal_add(SIGINT, on_terminate, NULL);

    start_settings_server();
    start_service();

    syslog(LOG_INFO, "%s started", APP_NAME);
    g_main_loop_run(main_loop);

    stop_service();
    for (gsize i = 0; i < G_N_ELEMENTS(parameters); i++)
        g_free(parameters[i].value);
    ax_parameter_free(parameter_handle);
    g_main_loop_unref(main_loop);
    closelog();
    return EXIT_SUCCESS;
}
