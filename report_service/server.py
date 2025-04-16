import grpc
from concurrent import futures
from report_service import report_pb2
from report_service import report_pb2_grpc
from report_service import db
import psycopg2
import csv
import json
import os
from datetime import datetime

def get_month_date_range(year, month):
    start = datetime(year, month, 1)
    if month == 12:
        end = datetime(year+1, 1, 1)
    else:
        end = datetime(year, month+1, 1)
    return start.date(), (end.date())

class ReportServiceServicer(report_pb2_grpc.ReportServiceServicer):
    def GenerateMonthlyReport(self, request, context):
        conn = db.get_conn()
        cur = conn.cursor()
        start_date, end_date = get_month_date_range(request.year, request.month)
        try:
            cur.execute("""
                SELECT category, tx_type as type, SUM(amount) as total
                FROM transactions
                WHERE user_id=%s AND date >= %s AND date < %s
                GROUP BY category, tx_type
            """, (request.user_id, start_date, end_date))
            rows = cur.fetchall()
            categories = {}
            total_income = 0.0
            total_expense = 0.0
            for row in rows:
                cat = row['category']
                if cat not in categories:
                    categories[cat] = {'income': 0.0, 'expense': 0.0}
                if row['type'] == 'income':
                    categories[cat]['income'] += row['total']
                    total_income += row['total']
                else:
                    categories[cat]['expense'] += row['total']
                    total_expense += row['total']
            cat_summaries = [
                report_pb2.CategorySummary(category=cat, income=val['income'], expense=val['expense'])
                for cat, val in categories.items()
            ]
            balance = total_income - total_expense
            report = report_pb2.MonthlyReport(
                user_id=request.user_id,
                year=request.year,
                month=request.month,
                total_income=total_income,
                total_expense=total_expense,
                balance=balance,
                categories=cat_summaries
            )
            return report_pb2.GenerateMonthlyReportResponse(report=report)
        except Exception as e:
            return report_pb2.GenerateMonthlyReportResponse()
        finally:
            cur.close()
            conn.close()

    def ExportReport(self, request, context):
        conn = db.get_conn()
        cur = conn.cursor()
        start_date, end_date = get_month_date_range(request.year, request.month)
        try:
            cur.execute("""
                SELECT category, tx_type as type, SUM(amount) as total
                FROM transactions
                WHERE user_id=%s AND date >= %s AND date < %s
                GROUP BY category, tx_type
            """, (request.user_id, start_date, end_date))
            rows = cur.fetchall()
            categories = {}
            total_income = 0.0
            total_expense = 0.0
            for row in rows:
                cat = row['category']
                if cat not in categories:
                    categories[cat] = {'income': 0.0, 'expense': 0.0}
                if row['type'] == 'income':
                    categories[cat]['income'] += row['total']
                    total_income += row['total']
                else:
                    categories[cat]['expense'] += row['total']
                    total_expense += row['total']
            cat_summaries = [
                {'category': cat, 'income': val['income'], 'expense': val['expense']}
                for cat, val in categories.items()
            ]
            balance = total_income - total_expense
            report_data = {
                'user_id': request.user_id,
                'year': request.year,
                'month': request.month,
                'total_income': total_income,
                'total_expense': total_expense,
                'balance': balance,
                'categories': cat_summaries
            }
            # Экспорт в файл
            file_dir = os.path.join(os.getcwd(), 'report_service', 'exports')
            os.makedirs(file_dir, exist_ok=True)
            filename = f"report_{request.user_id}_{request.year}_{request.month}.{request.format}"
            file_path = os.path.join(file_dir, filename)
            if request.format == 'json':
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, ensure_ascii=False, indent=2)
            elif request.format == 'csv':
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=['category', 'income', 'expense'])
                    writer.writeheader()
                    writer.writerows(cat_summaries)
            else:
                return report_pb2.ExportReportResponse(file_url="", status="unsupported format")
            return report_pb2.ExportReportResponse(file_url=file_path, status="exported")
        except Exception as e:
            return report_pb2.ExportReportResponse(file_url="", status=f"error: {str(e)}")
        finally:
            cur.close()
            conn.close()

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    report_pb2_grpc.add_ReportServiceServicer_to_server(ReportServiceServicer(), server)
    server.add_insecure_port('[::]:50053')
    print("ReportService gRPC server started on port 50053")
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    serve()
