/* Production storage and enrichment persistence, with bounded SQLite failures.
 * SQLITE_LIMIT_LENGTH is lowered to 1000 bytes. This tests SQLITE_TOOBIG
 * handling, not natural production-size inputs or out-of-memory behavior.
 * No networking or active fingerprint probes are executed. */
#include "enrichment_store.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

static int checks=0,failures=0;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; std::fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); } } while (0)
static void sql(sqlite3 *db,const char *s) {
  if(sqlite3_exec(db,s,nullptr,nullptr,nullptr)!=SQLITE_OK) {
    std::fprintf(stderr,"fixture SQL: %s\n",sqlite3_errmsg(db));std::exit(2);
  }
}
static std::string snapshot(sqlite3 *db) {
  sqlite3_stmt *st=nullptr;
  CHECK(sqlite3_prepare_v2(db,"SELECT * FROM hosts ORDER BY ip,port",-1,&st,nullptr)==SQLITE_OK);
  if(!st) std::exit(2);
  std::string result;int rc;
  while((rc=sqlite3_step(st))==SQLITE_ROW) {
    for(int i=0;i<sqlite3_column_count(st);++i) {
      result+=std::to_string(sqlite3_column_type(st,i))+":";
      const auto *data=static_cast<const char *>(sqlite3_column_blob(st,i));
      const int size=sqlite3_column_bytes(st,i);
      result+=std::to_string(size)+":";
      if(data)result.append(data,size);
      result+='|';
    }
    result+='\n';
  }
  CHECK(rc==SQLITE_DONE);CHECK(sqlite3_finalize(st)==SQLITE_OK);return result;
}
static sqlite3 *fixture() {
  sqlite3 *db=net_db_open(":memory:");CHECK(db);if(!db)std::exit(2);
  CHECK(net_db_insert_host(db,0xc0000201u,80,"tcp",1)==1);
  sqlite3_limit(db,SQLITE_LIMIT_LENGTH,1000);
  return db;
}
static void close_db(sqlite3 *db) {
  CHECK(sqlite3_next_stmt(db,nullptr)==nullptr);
  CHECK(sqlite3_get_autocommit(db));CHECK(sqlite3_close(db)==SQLITE_OK);
}
static void boundary(size_t length,bool transaction) {
  sqlite3 *db=fixture();if(transaction)CHECK(net_db_begin(db)==0);
  const auto before=snapshot(db);const std::string value(length,'x');
  const int rc=net_db_update_enrichment(db,"192.0.2.1",80,value.c_str(),"v2",nullptr,nullptr,nullptr,nullptr,nullptr);
  const bool success=length<=800;
  CHECK(success ? rc==0 : rc==-1);
  if(!success)CHECK(snapshot(db)==before);
  else {
    const auto rows=net_db_get_host(db,"192.0.2.1");CHECK(rows.size()==1);
    if(rows.size()==1)CHECK(rows[0].service==value&&rows[0].version=="v2"&&rows[0].enriched==1);
  }
  if(transaction)CHECK(net_db_commit(db)==0);
  if(!success)CHECK(snapshot(db)==before);
  std::printf("length=%zu outer=%d returned=%d expected=%d preserved=%d\n",length,transaction,rc,success?0:-1,snapshot(db)==before);
  if (!success) {
    CHECK(net_db_update_enrichment(db,"192.0.2.1",80,"retry","ok",nullptr,
                                  nullptr,nullptr,nullptr,nullptr)==0);
    const auto retry=net_db_get_host(db,"192.0.2.1");
    CHECK(retry.size()==1);
    if(retry.size()==1)CHECK(retry[0].service=="retry"&&retry[0].version=="ok");
  }
  close_db(db);
}
static void enrichment_fields() {
  const std::string too_big(1001,'x');
  for(int slot=0;slot<14;++slot) {
    sqlite3 *db=fixture();const auto before=snapshot(db);
    const char *v[12]={nullptr};v[slot==1?0:1]="changed";
    if(slot<12)v[slot]=too_big.c_str();
    const char *ip=slot==12?too_big.c_str():"192.0.2.1";
    const int rc=net_db_update_enrichment(db,ip,80,v[0],v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10],v[11]);
    if(slot<13){CHECK(rc==-1);CHECK(snapshot(db)==before);}
    else CHECK(rc==0); // ordinary small input remains supported
    close_db(db);
  }
}
static void neighboring_writes() {
  const std::string bad(1001,'x');
  for(int operation=0;operation<8;++operation) {
    sqlite3 *db=fixture();const auto before=snapshot(db);int rc=0;
    switch(operation) {
      case 0:rc=net_db_record_enrichment_error(db,"192.0.2.1",80,bad.c_str());break;
      case 1:rc=net_db_update_asn(db,"192.0.2.1",64512,bad.c_str(),"ZZ","prefix",nullptr,nullptr);break;
      case 2:rc=net_db_set_hostname(db,"192.0.2.1",bad.c_str());break;
      case 3:rc=net_db_update_cloud(db,"192.0.2.1",bad.c_str(),"region","service");break;
      case 4:rc=net_db_set_screenshot(db,"192.0.2.1",80,bad.c_str());break;
      case 5:rc=net_db_update_tls(db,"192.0.2.1",80,bad.c_str(),"issuer",nullptr,nullptr,1,"TLS",nullptr);break;
      case 6:rc=net_db_insert_host(db,0xc0000202u,81,bad.c_str(),2);break;
      case 7:rc=net_db_update_cloud(db,bad.c_str(),"provider","region","service");break;
    }
    CHECK(rc==-1);CHECK(snapshot(db)==before);close_db(db);
  }
}

static std::string value(sqlite3 *db, const char *column) {
  const std::string query=std::string("SELECT ")+column+" FROM hosts ORDER BY port LIMIT 1";
  sqlite3_stmt *st=nullptr;
  CHECK(sqlite3_prepare_v2(db,query.c_str(),-1,&st,nullptr)==SQLITE_OK);
  if(!st)std::exit(2);
  CHECK(sqlite3_step(st)==SQLITE_ROW);
  const auto *text=sqlite3_column_text(st,0);
  const std::string result=text?reinterpret_cast<const char *>(text):"<NULL>";
  CHECK(sqlite3_finalize(st)==SQLITE_OK);return result;
}

static void optional_values() {
  sqlite3 *db=fixture();
  CHECK(net_db_update_enrichment(db,"192.0.2.1",80,"service","version","[]",
    "title","server","headers","paths","powered","generator","redirect","[]","cpe")==0);
  CHECK(net_db_update_enrichment(db,"192.0.2.1",80,nullptr,"",nullptr,
    "",nullptr,"",nullptr,"",nullptr,"",nullptr,"")==0);
  const char *columns[]={"service","version","cves","web_title","web_server","web_headers",
    "web_paths","powered_by","x_generator","redirect_target","robots_disallowed_json","cpe"};
  const char *expected[]={"service","version","[]","title","server","headers","paths",
    "powered","generator","redirect","[]","cpe"};
  for(size_t i=0;i<12;++i)CHECK(value(db,columns[i])==expected[i]);
  CHECK(net_db_update_asn(db,"192.0.2.1",64512,"name","ZZ","prefix","registry","region")==0);
  CHECK(net_db_update_asn(db,"192.0.2.1",0xffffffffu,nullptr,"",nullptr,"",nullptr)==0);
  CHECK(value(db,"asn")=="4294967295");CHECK(value(db,"as_name")=="name");
  CHECK(value(db,"country")=="ZZ");CHECK(value(db,"bgp_prefix")=="prefix");
  CHECK(value(db,"asn_registry")=="registry");CHECK(value(db,"asn_region")=="region");
  CHECK(net_db_update_cloud(db,"192.0.2.1","provider","region","service")==0);
  CHECK(net_db_update_cloud(db,"192.0.2.1","",nullptr,"")==0);
  CHECK(value(db,"cloud_provider")=="provider");CHECK(value(db,"cloud_region")=="region");
  CHECK(value(db,"cloud_service")=="service");
  CHECK(net_db_update_tls(db,"192.0.2.1",80,"cn","issuer","[]","expiry",1,"TLS","sha")==0);
  CHECK(net_db_update_tls(db,"192.0.2.1",80,"",nullptr,"",nullptr,-1,"",nullptr)==0);
  CHECK(value(db,"tls_subject_cn")=="cn");CHECK(value(db,"tls_issuer")=="issuer");
  CHECK(value(db,"tls_san_json")=="[]");CHECK(value(db,"tls_not_after")=="expiry");
  CHECK(value(db,"tls_self_signed")=="1");CHECK(value(db,"tls_protocol")=="TLS");
  CHECK(value(db,"tls_sha256")=="sha");
  CHECK(net_db_set_hostname(db,"192.0.2.1","name")==0);
  CHECK(net_db_set_hostname(db,"192.0.2.1","")==0);
  CHECK(value(db,"hostname")=="<NULL>");
  CHECK(net_db_set_screenshot(db,"192.0.2.1",80,"fixture.png")==0);
  CHECK(net_db_set_screenshot(db,"192.0.2.1",80,nullptr)==0);
  CHECK(value(db,"screenshot_path")=="<NULL>");
  CHECK(net_db_record_enrichment_error(db,"192.0.2.1",80,"failure")==0);
  CHECK(net_db_record_enrichment_error(db,"192.0.2.1",80,"")==0);
  CHECK(value(db,"enrichment_error")=="<NULL>");
  close_db(db);
}

static void metadata_bind_positions() {
  const std::string bad(1001,'x');
  for(int kind=0;kind<3;++kind)for(int slot=0;slot<(kind==0?6:kind==1?4:7);++slot) {
    sqlite3 *db=fixture();CHECK(net_db_begin(db)==0);
    const auto before=snapshot(db);const char *v[6]={nullptr};
    const int fields=kind==0?5:kind==1?3:6;
    if(slot<fields)v[slot]=bad.c_str();
    const char *ip=slot==fields?bad.c_str():"192.0.2.1";
    int rc;
    if(kind==0)rc=net_db_update_asn(db,ip,64512,v[0],v[1],v[2],v[3],v[4]);
    else if(kind==1)rc=net_db_update_cloud(db,ip,v[0],v[1],v[2]);
    else rc=net_db_update_tls(db,ip,80,v[0],v[1],v[2],v[3],1,v[4],v[5]);
    CHECK(rc==-1);CHECK(snapshot(db)==before);
    CHECK(!sqlite3_get_autocommit(db));CHECK(net_db_commit(db)==0);
    CHECK(snapshot(db)==before);close_db(db);
  }
}

static std::string no_cpe(const std::string &,const std::string &) { return ""; }
static void caller_rolls_back() {
  for(int failure=0;failure<3;++failure) {
    sqlite3 *db=fixture();CHECK(net_db_insert_host(db,0xc0000202u,80,"tcp",1)==1);
    const auto before=snapshot(db);
    NetEnrichResult first;first.shard_idx=0;first.ip="192.0.2.1";
    first.ports={80};first.services={"valid"};first.versions={"1"};
    NetEnrichResult second=first;second.ip="192.0.2.2";
    if(failure==0)second.hostname=std::string(1001,'x');
    if(failure==1)second.services[0]=std::string(1001,'x');
    if(failure==2)second.cloud_info.provider=std::string(1001,'x');
    const auto failed=net_store_enrichment_results({db},{first,second},no_cpe);
    CHECK(failed.written==0);CHECK(failed.failed_shards==1);
    CHECK(snapshot(db)==before);CHECK(sqlite3_get_autocommit(db));
    CHECK(sqlite3_next_stmt(db,nullptr)==nullptr);
    second.hostname.clear();second.services[0]="retry";second.cloud_info.provider.clear();
    const auto retry=net_store_enrichment_results({db},{first,second},no_cpe);
    CHECK(retry.written==2);CHECK(retry.failed_shards==0);
    CHECK(net_db_get_host(db,"192.0.2.1")[0].service=="valid");
    CHECK(net_db_get_host(db,"192.0.2.2")[0].service=="retry");
    close_db(db);
  }
}

int main() {
  for(bool transaction:{false,true})for(size_t length:{16u,800u,999u,1000u,1001u,2000u})boundary(length,transaction);
  enrichment_fields();neighboring_writes();
  optional_values();metadata_bind_positions();caller_rolls_back();
  std::printf("bind failures: checks=%d failures=%d\n",checks,failures);
  return failures?1:0;
}
