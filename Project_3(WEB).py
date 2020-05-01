from flask import Flask, render_template, make_response, request
from flask_login import LoginManager, login_required, logout_user, login_user
from werkzeug.utils import redirect
from data import db_session
from data.registry import RegisterForm, LoginForm
from data.users import User
from data.news import News
import os

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'

@login_manager.user_loader
def load_user(user_id):
    session = db_session.create_session()
    return session.query(User).get(user_id)

@app.route('/')
def index():
    session = db_session.create_session()
    news = session.query(News).filter(News.is_private != True)
    return render_template("mainindexx.html", news=news)

@app.route('/register', methods=['GET', 'POST'])
def reqister():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('registry.html', title='Регистрация',
                                       form=form,
                                       message="Пароли не совпадают")
        session = db_session.create_session()
        if session.query(User).filter(User.email == form.email.data).first():
            return render_template('registry.html', title='Регистрация',
                                       form=form,
                                       message="Такой пользователь уже есть")
        user = User(name=form.name.data, surname=form.surname.data,
                    email=form.email.data, schizm=form.schizm.data)
        user.set_password(form.password.data)
        session.add(user)
        session.commit()
        return redirect('/login')
    return render_template('registry.html', title='Регистрация', form=form)

@app.route("/cookie_test")
def cookie_test():
    visits_count = int(request.cookies.get("visits_count", 0))
    if visits_count:
        res = make_response(f"Вы пришли на эту страницу {visits_count + 1} раз")
        res.set_cookie("visits_count", str(visits_count + 1),
                       max_age=60 * 60 * 24 * 365 * 2)
    else:
        res = make_response(
            "Вы пришли на эту страницу в первый раз за последний год")
        res.set_cookie("visits_count", '1',
                       max_age=60 * 60 * 24 * 365)
    return res

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        session = db_session.create_session()
        user = session.query(User).filter(User.email == form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect("/")
        return render_template('login.html',
                               message="Неправильный логин или пароль",
                               form=form)
    return render_template('login.html', title='Авторизация', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


db_session.global_init("db/steam.sqlite")
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(threaded=True, port=5000)
