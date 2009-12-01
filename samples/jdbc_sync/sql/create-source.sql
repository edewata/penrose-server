-- users --

create table users (
    username varchar(50),
    firstName varchar(50),
    lastName varchar(50),
    password varchar(10),
    primary key (username)
);

create table users_changelog (
    changeNumber integer auto_increment,
    changeTime datetime,
    changeAction varchar(10),
    changeUser varchar(10),
    username varchar(50),
    firstName varchar(50),
    lastName varchar(50),
    password varchar(10),
    primary key (changeNumber)
);

create trigger users_add after insert on users
for each row
    insert into users_changelog values (
        null, now(), 'ADD', substring_index(user(),_utf8'@',1),
        new.username, new.firstName, new.lastName, new.password
    )
;

delimiter |
create trigger users_modify after update on users
for each row begin
    if new.username = old.username then
        insert into users_changelog values (
            null, now(), 'MODIFY', substring_index(user(),_utf8'@',1),
            new.username, new.firstName, new.lastName, new.password
        );
    else
        insert into users_changelog values (
            null, now(), 'DELETE', substring_index(user(),_utf8'@',1),
            old.username, old.firstName, old.lastName, old.password
        );
        insert into users_changelog values (
            null, now(), 'ADD', substring_index(user(),_utf8'@',1),
            new.username, new.firstName, new.lastName, new.password
        );
    end if;
end;|
delimiter ;

create trigger users_delete after delete on users
for each row
    insert into users_changelog values (
        null, now(), 'DELETE', substring_index(user(),_utf8'@',1),
        old.username, old.firstName, old.lastName, old.password
    )
;

-- groups --

create table groups (
    groupname varchar(50),
    primary key (groupname)
);

create table groups_changelog (
    changeNumber integer auto_increment,
    changeTime datetime,
    changeAction varchar(10),
    changeUser varchar(10),
    groupname varchar(50),
    primary key (changeNumber)
);

create trigger groups_add after insert on groups
for each row
    insert into groups_changelog values (
        null, now(), 'ADD', substring_index(user(),_utf8'@',1),
        new.groupname
    )
;

delimiter |
create trigger groups_modify after update on groups
for each row begin
    if new.groupname = old.groupname then
        insert into groups_changelog values (
            null, now(), 'MODIFY', substring_index(user(),_utf8'@',1),
            new.groupname
        );
    else
        insert into groups_changelog values (
            null, now(), 'DELETE', substring_index(user(),_utf8'@',1),
            old.groupname
        );
        insert into groups_changelog values (
            null, now(), 'ADD', substring_index(user(),_utf8'@',1),
            new.groupname
        );
    end if;
end;|
delimiter ;

create trigger groups_delete after delete on groups
for each row
    insert into groups_changelog values (
        null, now(), 'DELETE', substring_index(user(),_utf8'@',1),
        old.groupname
    )
;

-- usergroups --

create table usergroups (
    groupname varchar(50),
    username varchar(50),
    primary key (groupname, username)
);

create table usergroups_changelog (
    changeNumber integer auto_increment,
    changeTime datetime,
    changeAction varchar(10),
    changeUser varchar(10),
    groupname varchar(50),
    username varchar(50),
    primary key (changeNumber)
);

create trigger usergroups_add after insert on usergroups
for each row
    insert into usergroups_changelog values (
        null, now(), 'ADD', substring_index(user(),_utf8'@',1),
        new.groupname, new.username
    )
;

delimiter |
create trigger usergroups_modify after update on usergroups
for each row begin
    if new.groupname = old.groupname and new.username = old.username then
        insert into usergroups_changelog values (
            null, now(), 'MODIFY', substring_index(user(),_utf8'@',1),
            new.groupname, new.username
        );
    else
        insert into usergroups_changelog values (
            null, now(), 'DELETE', substring_index(user(),_utf8'@',1),
            old.groupname, old.username
        );
        insert into usergroups_changelog values (
            null, now(), 'ADD', substring_index(user(),_utf8'@',1),
            new.groupname, new.username
        );
    end if;
end;|
delimiter ;

create trigger usergroups_delete after delete on usergroups
for each row
    insert into usergroups_changelog values (
        null, now(), 'DELETE', substring_index(user(),_utf8'@',1),
        old.groupname, old.username
    )
;
