create table if not exists settings(key text primary key, value text not null);
alter table settings enable row level security;
insert into settings values
('admin_number','841413664'),
('deposit_steps',E'1. Marca *150# na chamada\n2. Escolhe 1 (Transferir dinheiro)\n3. Escolhe 1 (Número M-Pesa)\n4. Escreve o número do administrador: {numero}\n5. Escreve o valor e confirma com o teu PIN\n6. No SMS de confirmação, copia a referência da transacção\n7. Cola a referência no campo "Referência" aqui na app, escreve o valor e toca em Depositar\n8. Espera a aprovação do administrador'),
('loss_limit','200'),('hh_bonus','10'),('hh_text','Bónus nos depósitos feitos agora!'),
('hh_salt',encode(extensions.gen_random_bytes(8),'hex')),('hh_manual_until','0'),('hh_manual_text','')
on conflict (key) do nothing;

alter table requests add column if not exists ref text;
alter table requests add column if not exists bonus_pct numeric not null default 0;
create unique index if not exists requests_ref_uk on requests (upper(ref)) where ref is not null;

create or replace function hh_sched(d date) returns table(s timestamptz, e timestamptz) language sql stable security definer set search_path=public,extensions as $$
select ((d + time '09:00') + ((i*240 + (get_byte(h,0)*256+get_byte(h,1))%196) * interval '1 minute')) at time zone 'Africa/Maputo',
       ((d + time '09:00') + ((i*240 + (get_byte(h,0)*256+get_byte(h,1))%196 + 45) * interval '1 minute')) at time zone 'Africa/Maputo'
from generate_series(0,2) i, lateral (select digest(d::text||':'||i||':'||(select value from settings where key='hh_salt'),'sha256') h) x $$;
revoke execute on function hh_sched(date) from public, anon, authenticated;

create or replace function hh_now() returns json language plpgsql stable security definer set search_path=public,extensions as $$
declare mu bigint:=coalesce((select value::bigint from settings where key='hh_manual_until'),0); d date:=(now() at time zone 'Africa/Maputo')::date; r record; bonus numeric:=coalesce((select value::numeric from settings where key='hh_bonus'),10);
begin
 if mu>extract(epoch from now()) then return json_build_object('on',true,'manual',true,'text',(select value from settings where key='hh_manual_text'),'until',mu*1000,'bonus',bonus); end if;
 for r in select * from hh_sched(d) loop
  if now()>=r.s and now()<r.e then return json_build_object('on',true,'manual',false,'text',(select value from settings where key='hh_text'),'until',(extract(epoch from r.e)*1000)::bigint,'bonus',bonus); end if;
 end loop;
 return json_build_object('on',false);
end $$;

create or replace function extras() returns json language plpgsql security definer set search_path=public,extensions as $$
declare uid uuid:=auth.uid(); lim numeric:=coalesce((select value::numeric from settings where key='loss_limit'),200); lost numeric; num text; adm boolean:=is_admin(); sc json; cfg json; d date:=(now() at time zone 'Africa/Maputo')::date;
begin
 if uid is null then raise exception 'Sem sessão'; end if;
 select coalesce(sum(bet-pay),0) into lost from spins where user_id=uid and (ts at time zone 'Africa/Maputo')::date=d;
 select value into num from settings where key='admin_number';
 if adm then
  select json_agg(json_build_object('from',to_char(s at time zone 'Africa/Maputo','HH24:MI'),'to',to_char(e at time zone 'Africa/Maputo','HH24:MI')) order by s) into sc from hh_sched(d);
  cfg:=json_build_object('number',num,'limit',lim,'bonus',(select value from settings where key='hh_bonus'),'steps',(select value from settings where key='deposit_steps'),'text',(select value from settings where key='hh_text'));
 end if;
 return json_build_object('steps',replace((select value from settings where key='deposit_steps'),'{numero}',coalesce(num,'')),'number',num,'limit',lim,'lost',lost,'hh',hh_now(),'sched',sc,'cfg',cfg);
end $$;

create or replace function admin_set(p_key text, p_value text) returns void language plpgsql security definer set search_path=public as $$
begin
 if not is_admin() then raise exception 'Sem permissão'; end if;
 if p_key not in ('admin_number','deposit_steps','loss_limit','hh_bonus','hh_text') then raise exception 'Definição inválida'; end if;
 if p_key in ('loss_limit','hh_bonus') and p_value !~ '^[0-9]+(\.[0-9]+)?$' then raise exception 'Valor numérico inválido'; end if;
 if p_key='admin_number' and p_value !~ '^[0-9 +]{9,15}$' then raise exception 'Número inválido'; end if;
 update settings set value=left(p_value,1000) where key=p_key;
end $$;

create or replace function admin_happy(p_text text, p_minutes int) returns void language plpgsql security definer set search_path=public as $$
begin
 if not is_admin() then raise exception 'Sem permissão'; end if;
 if p_minutes<=0 then update settings set value='0' where key='hh_manual_until'; return; end if;
 update settings set value=left(coalesce(nullif(trim(p_text),''),(select value from settings where key='hh_text')),140) where key='hh_manual_text';
 update settings set value=(extract(epoch from now())::bigint+least(p_minutes,240)*60)::text where key='hh_manual_until';
end $$;

create or replace function request_money2(p_kind text, p_amount numeric, p_ref text) returns void language plpgsql security definer set search_path=public as $$
declare uid uuid:=auth.uid(); rid bigint; rf text:=upper(trim(coalesce(p_ref,''))); b numeric:=0; h json:=hh_now();
begin
 if uid is null then raise exception 'Sem sessão'; end if;
 if p_kind<>'dep' then raise exception 'Só para depósitos'; end if;
 if rf !~ '^[A-Z0-9.\-]{6,30}$' then raise exception 'Referência inválida'; end if;
 if exists(select 1 from requests where upper(requests.ref)=rf) then raise exception 'Esta referência já foi usada.'; end if;
 perform request_money('dep',p_amount);
 if (h->>'on')::boolean then b:=(h->>'bonus')::numeric; end if;
 select max(id) into rid from requests where user_id=uid and kind='dep' and status='pend';
 update requests set ref=rf, bonus_pct=b where id=rid;
end $$;

create or replace function req_bonus() returns trigger language plpgsql security definer set search_path=public as $$
declare bn numeric; bk numeric;
begin
 if new.kind='dep' and new.status='ok' and old.status='pend' and coalesce(new.bonus_pct,0)>0 then
  select amount into bk from bank where id=1 for update;
  bn:=least(round(new.amount*new.bonus_pct/100,2),bk);
  if bn>0 then
   update profiles set bal=bal+bn where id=new.user_id;
   update bank set amount=amount-bn where id=1;
   insert into movements(user_id,username,kind,amount) values(new.user_id,new.username,'bonus',bn);
  end if;
 end if;
 return new;
end $$;
drop trigger if exists req_bonus_trg on requests;
create trigger req_bonus_trg after update on requests for each row execute function req_bonus();

create or replace function spins_limit() returns trigger language plpgsql security definer set search_path=public as $$
declare lim numeric:=coalesce((select value::numeric from settings where key='loss_limit'),200); lost numeric;
begin
 select coalesce(sum(bet-pay),0) into lost from spins where user_id=new.user_id and (ts at time zone 'Africa/Maputo')::date=(now() at time zone 'Africa/Maputo')::date;
 if lost+new.bet>lim then raise exception 'Limite diário de perda (% MT) atingido para esta aposta. Tenta uma aposta menor ou volta amanhã.',lim; end if;
 return new;
end $$;
drop trigger if exists spins_limit_trg on spins;
create trigger spins_limit_trg before insert on spins for each row execute function spins_limit();
