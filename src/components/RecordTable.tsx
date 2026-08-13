import { bindRecord } from '../core/dns/presentation';
import { parseRecordView } from '../core/dns/records';
import type { DnsRecord } from '../core/dns/types';

interface RecordTableProps {
  readonly records: readonly DnsRecord[];
}

export function RecordTable({ records }: RecordTableProps) {
  if (records.length === 0) return <p className="empty-note">No records in this section.</p>;

  return (
    <div className="table-scroll">
      <table>
        <caption className="visually-hidden">DNS resource records</caption>
        <thead>
          <tr>
            <th scope="col">Owner</th>
            <th scope="col">TTL</th>
            <th scope="col">Type</th>
            <th scope="col">Record data</th>
          </tr>
        </thead>
        <tbody>
          {records.map((record, index) => {
            const view = parseRecordView(record);
            return (
              <tr key={`${record.section}-${record.owner}-${record.type}-${String(index)}`}>
                <td className="record-data">{record.owner}</td>
                <td>{record.ttl}</td>
                <td>{record.type}</td>
                <td>
                  <code className="record-value">{view.text}</code>
                  {view.fields.length > 1 ? (
                    <dl className="record-fields">
                      {view.fields.map((item) => (
                        <div key={item.label}>
                          <dt>{item.label}</dt>
                          <dd>{item.value}</dd>
                        </div>
                      ))}
                    </dl>
                  ) : null}
                  <span className="visually-hidden">{bindRecord(record)}</span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
