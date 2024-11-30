__END_DECLS char *hosts_info (struct from_host *client)
{
    static char buf[BUFSIZ];		/* XXX */

    if (client->user[0] && strcmp(client->user, FROM_UNKNOWN)) {
	sprintf(buf, "%s@%s", client->user, FROM_HOST(client));
	return (buf);
    } else {
	return (FROM_HOST(client));
    }
}
