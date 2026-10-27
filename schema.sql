-- ROLETA DOS AMIGOS: cola tudo isto no Supabase > SQL Editor > Run.
-- ANTES de correr: troca 'TROCA-ESTE-CODIGO' por um código teu (será o código do administrador).
create extension if not exists pgcrypto with schema extensions;

create table profiles(id uuid primary key references auth.users on delete cascade, username text unique not null, bal numeric(12,2) not null default 0, is_admin boolean not null default false);
create table invites(code text primary key, is_admin boolean not null default false, used boolean not null default false);
create table bank(id int primary key, amount numeric(12,2) not null);
create table secret(id int primary key, seed text not null, nonce bigint not null default 0);
create table spins(id bigserial primary key, user_id uuid, username text, bet numeric(12,2), mult numeric, pay numeric(12,2), seed text, commit_hash text, cs text, n bigint, ts timestamptz default now());
create table movements(id bigserial primary key, user_id uuid, username text, kind text, amount numeric(12,2), ts timestamptz default now());

insert into bank values(1,1000);
insert into secret values(1,encode(extensions.gen_random_bytes(32),'hex'),0);
insert into invites values('TROCA-ESTE-CODIGO',true,false);

alter table profiles enable row level security; alter table invites enable row level security; alter table bank enable row level security;
alter table secret enable row level security; alter table spins enable row level security; alter table movements enable row level security;

create function is_admin() returns boolean language sql security definer stable set search_path=public as $$ select coalesce((select is_admin from profiles where id=auth.uid()),false) $$;
create policy p_sel on profiles for select to authenticated using (id=auth.uid() or is_admin());
create policy i_sel on invites for select to authenticated using (is_admin());
create policy b_sel on bank for select to authenticated using (true);
create policy s_sel on spins for select to authenticated using (true);
create policy m_sel on movements for select to authenticated using (user_id=auth.uid() or is_admin());
-- Ninguém tem permissão para escrever directamente: só as funções abaixo mexem em saldos.

create function handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
declare inv invites; u text:=lower(coalesce(new.raw_user_meta_data->>'username',''));
begin
 select * into inv from invites where code=new.raw_user_meta_data->>'code' and not used for update;
 if not found then raise exception 'Convite inválido'; end if;
 if u !~ '^[a-z][a-z0-9]{2,15}$' then raise exception 'Utilizador inválido'; end if;
 if (select count(*) from profiles)>=12 then raise exception 'Grupo cheio'; end if;
 insert into profiles(id,username,is_admin) values(new.id,u,inv.is_admin);
 update invites set used=true where code=inv.code;
 return new;
end $$;
create trigger on_auth_user after insert on auth.users for each row execute function handle_new_user();

create function state() returns json language sql security definer set search_path=public,extensions as $$
 select json_build_object('bank',b.amount,'maxBet',floor(b.amount/99),'commit',encode(digest(s.seed,'sha256'),'hex')) from bank b,secret s where b.id=1 and s.id=1 $$;

create function spin(p_bet numeric, p_cs text) returns json language plpgsql security definer set search_path=public,extensions as $$
declare uid uuid:=auth.uid(); p profiles; s secret; b bank; k int; m numeric; pay numeric; mx numeric; cm text; sd text; nn bigint; nb numeric; nk numeric;
begin
 if uid is null then raise exception 'Sem sessão'; end if;
 select * into p from profiles where id=uid for update;
 select * into s from secret where id=1 for update;
 select * into b from bank where id=1 for update;
 p_bet:=round(coalesce(p_bet,0),2); mx:=floor(b.amount/99);
 if p_bet<=0 or p_bet>mx then raise exception 'Aposta máxima agora: % MT',mx; end if;
 if p_bet>p.bal then raise exception 'Saldo insuficiente'; end if;
 p_cs:=left(coalesce(p_cs,''),32); sd:=s.seed; nn:=s.nonce; cm:=encode(digest(sd,'sha256'),'hex');
 k:=(('x'||encode(substring(hmac(p_cs||':'||nn,sd,'sha256') from 1 for 6),'hex'))::bit(48)::bigint % 1000)::int;
 m:=case when k<430 then 0 when k<680 then 0.5 when k<820 then 1 when k<900 then 1.5 when k<945 then 2 when k<970 then 3 when k<985 then 5 when k<993 then 10 when k<997 then 20 when k<999 then 50 else 100 end;
 pay:=round(p_bet*m,2);
 update profiles set bal=bal-p_bet+pay where id=uid returning bal into nb;
 update bank set amount=amount+p_bet-pay where id=1 returning amount into nk;
 insert into spins(user_id,username,bet,mult,pay,seed,commit_hash,cs,n) values(uid,p.username,p_bet,m,pay,sd,cm,p_cs,nn);
 update secret set seed=encode(gen_random_bytes(32),'hex'),nonce=nonce+1 where id=1;
 return json_build_object('m',m,'pay',pay,'bal',nb,'seed',sd,'commit',cm,'n',nn,'bank',nk,'maxBet',floor(nk/99));
end $$;

create function admin_credit(p_user text, p_amount numeric) returns void language plpgsql security definer set search_path=public as $$
declare t profiles; v numeric:=round(coalesce(p_amount,0),2);
begin
 if not is_admin() then raise exception 'Sem permissão'; end if;
 select * into t from profiles where username=lower(p_user) for update;
 if not found or v=0 then raise exception 'Dados inválidos'; end if;
 if t.bal+v<0 then raise exception 'Saldo insuficiente'; end if;
 update profiles set bal=bal+v where id=t.id;
 insert into movements(user_id,username,kind,amount) values(t.id,t.username,case when v>0 then 'dep' else 'wd' end,abs(v));
end $$;

create function admin_bank(p_amount numeric) returns void language plpgsql security definer set search_path=public as $$
declare v numeric:=round(coalesce(p_amount,0),2); cur numeric;
begin
 if not is_admin() then raise exception 'Sem permissão'; end if;
 select amount into cur from bank where id=1 for update;
 if v=0 or cur+v<0 then raise exception 'Valor inválido'; end if;
 update bank set amount=amount+v where id=1;
 insert into movements(user_id,username,kind,amount) select id,username,'bank',v from profiles where id=auth.uid();
end $$;

create function admin_invite() returns text language plpgsql security definer set search_path=public,extensions as $$
declare k text:='AMIGO-'||upper(encode(gen_random_bytes(4),'hex'));
begin
 if not is_admin() then raise exception 'Sem permissão'; end if;
 insert into invites(code) values(k); return k;
end $$;

alter publication supabase_realtime add table spins, profiles, bank;
